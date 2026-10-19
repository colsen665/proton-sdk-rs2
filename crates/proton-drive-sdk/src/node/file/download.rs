use crate::client::ProtonDriveClient;
use crate::node::download::{ControllerState, DownloadController};
use crate::node::revision::{RevisionOperations, RevisionUid};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

pub struct FileDownloader {
    client: Arc<ProtonDriveClient>,
    revision_uid: RevisionUid,
    remaining_number_of_blocks_to_list: AtomicI32,
}

impl FileDownloader {
    pub async fn create(
        client: &ProtonDriveClient,
        revision_uid: RevisionUid,
    ) -> anyhow::Result<Self> {
        client.block_listing_semaphore().acquire(1).await?;

        Ok(Self {
            client: Arc::new(client.clone()),
            revision_uid,
            remaining_number_of_blocks_to_list: AtomicI32::new(1),
        })
    }

    /// Downloads the whole revision to `content_output_stream`.
    ///
    /// Every block's hash is checked, and the manifest signature is verified once
    /// all blocks are written. If only the manifest check fails, the content has
    /// been written, the task returns
    /// [`crate::node::download::CompletedDownloadManifestVerificationException`],
    /// and [`DownloadController::get_is_download_complete_with_verification_issue`]
    /// returns `true`.
    pub fn download_to_stream(
        &self,
        mut content_output_stream: Box<dyn std::io::Write + Send>,
        on_progress: Box<dyn Fn(i64, i64) + Send + Sync>,
    ) -> DownloadController {
        let client = self.client.clone();
        let revision_uid = self.revision_uid.clone();

        let (state_tx, state_rx) = tokio::sync::watch::channel(ControllerState::Running);
        let verification_issue = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_verification_issue = verification_issue.clone();

        let completion = tokio::spawn(async move {
            let _file_permit = client.block_downloader().queue.start_file().await?;
            let release_block_listing = Box::new(|_| {});
            tracing::debug!("Creating download state for revision_uid={}", revision_uid);
            let download_state = RevisionOperations::create_download_state(
                &client,
                revision_uid.clone(),
                release_block_listing,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to create download state for {}: {:?}",
                    revision_uid,
                    e
                );
                e
            })?;

            let num_blocks = download_state.revision_dto.blocks.len();
            tracing::debug!(
                "Download state created: {} blocks, size={}",
                num_blocks,
                download_state.revision_dto.revision.size
            );

            let metric_item = crate::telemetry::MetricItem::from_revision(
                &revision_uid.node_uid,
                &download_state.revision_dto.revision,
            );
            let download_state = Arc::new(download_state);
            let reader = RevisionOperations::open_for_reading(
                &client,
                download_state.clone(),
                Box::new(|_| {}),
            );

            // Use parallel downloads for better performance (downloads up to 5 blocks concurrently)
            let result = reader
                .read_all_blocks_parallel(
                    &mut *content_output_stream,
                    |downloaded, total| {
                        on_progress(downloaded, total);
                    },
                    Some(state_rx),
                )
                .await;

            if let Err(e) = &result {
                if e.downcast_ref::<crate::node::download::CompletedDownloadManifestVerificationException>()
                    .is_some()
                {
                    task_verification_issue.store(true, Ordering::Relaxed);
                }
                if e.downcast_ref::<crate::node::download::FileContentsDecryptionException>()
                    .is_some()
                {
                    client
                        .integrity_reporter()
                        .report(
                            &client,
                            &metric_item,
                            "content",
                            Some(&e.to_string()),
                            false,
                            None,
                        )
                        .await;
                }
                client
                    .telemetry()
                    .record_metric("downloadError".into(), Some(e.to_string().into_bytes()))
                    .await;
            }
            result?;

            // Ensure all buffered data is flushed before returning
            content_output_stream.flush()?;

            Ok(())
        });

        DownloadController::with_verification_issue_flag(
            state_tx,
            completion,
            self.client.sdk_events().clone(),
            verification_issue,
        )
    }

    /// Claimed plaintext sizes of each block, required for seeking. Fails on older files that omit them.
    pub async fn claimed_block_sizes(&self) -> anyhow::Result<Vec<i32>> {
        let secrets = crate::node::file::FileOperations::get_secrets(
            &self.client,
            self.revision_uid.node_uid.clone(),
        )
        .await?;
        crate::node::file::block_map::listed_claimed_block_sizes(
            &self.client,
            &self.revision_uid,
            &secrets.base.key,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("revision has no claimed block sizes"))
    }

    /// Downloads `[offset, offset+length)` of plaintext using claimed block sizes.
    ///
    /// Each downloaded block's hash is checked, but a ranged read cannot verify the
    /// revision manifest signature, which covers all blocks. Use
    /// [`Self::download_to_stream`] for an authenticated full download.
    ///
    /// Each call builds a new [`crate::node::file::block_map::BlockMap`]. For many
    /// reads of the same revision, build one with
    /// [`ProtonDriveClient::get_block_map`] and use
    /// [`ProtonDriveClient::download_block`].
    pub async fn download_range(
        &self,
        offset: u64,
        length: u64,
        output: &mut dyn std::io::Write,
    ) -> anyhow::Result<u64> {
        let map = self.client.get_block_map(self.revision_uid.clone()).await?;
        let mut written = 0u64;
        for slice in map.blocks_for_range(offset, length)? {
            let data = self.client.download_block(&map, slice.index).await?;
            output.write_all(&data[slice.start as usize..slice.end as usize])?;
            written += slice.end - slice.start;
        }
        Ok(written)
    }

    /// Creates a cursor for on-demand range reads, suitable for media playback.
    pub async fn get_seekable_stream(&self) -> anyhow::Result<SeekableFileStream<'_>> {
        let length =
            self.claimed_block_sizes()
                .await?
                .into_iter()
                .try_fold(0u64, |total, size| {
                    u64::try_from(size)
                        .ok()
                        .and_then(|size| total.checked_add(size))
                        .ok_or_else(|| anyhow::anyhow!("invalid claimed block sizes"))
                })?;
        Ok(SeekableFileStream {
            downloader: self,
            position: 0,
            length,
        })
    }
}

pub struct SeekableFileStream<'a> {
    downloader: &'a FileDownloader,
    position: u64,
    length: u64,
}

impl SeekableFileStream<'_> {
    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn seek(&mut self, position: u64) -> anyhow::Result<()> {
        if position > self.length {
            anyhow::bail!(
                "seek position {position} exceeds file length {}",
                self.length
            );
        }
        self.position = position;
        Ok(())
    }

    pub async fn read(&mut self, num_bytes: usize) -> anyhow::Result<Vec<u8>> {
        if num_bytes == 0 {
            anyhow::bail!("read length must be greater than zero");
        }
        let mut bytes = Vec::with_capacity(num_bytes.min((self.length - self.position) as usize));
        let written = self
            .downloader
            .download_range(self.position, num_bytes as u64, &mut bytes)
            .await?;
        self.position += written;
        Ok(bytes)
    }
}

impl Drop for FileDownloader {
    fn drop(&mut self) {
        let remaining = self
            .remaining_number_of_blocks_to_list
            .swap(0, Ordering::SeqCst);
        if remaining > 0 {
            self.client
                .block_listing_semaphore()
                .release(remaining as usize);
        }
    }
}
