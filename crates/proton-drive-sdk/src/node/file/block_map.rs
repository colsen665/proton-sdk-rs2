//! Reusable block map of a file revision, for random block access.
//!
//! A [`BlockMap`] holds what is needed to download any block of a revision
//! without listing the revision again: the content key, each block's storage
//! URL, token and hash, and, when the uploader declared them, the plaintext
//! block sizes used to map byte offsets to blocks.

use crate::api::block::BlockDto;
use crate::client::ProtonDriveClient;
use crate::node::NodeUid;
use crate::node::revision::{RevisionOperations, RevisionUid};
use crate::pgp::{PgpArmoredMessage, PgpPrivateKey, PgpSessionKey};

/// One block of a [`BlockMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMapEntry {
    /// One-based block index.
    pub index: i32,
    /// Storage URL of the encrypted block. It expires; see [`BlockMap::refresh_urls`].
    pub bare_url: String,
    /// Storage token for `bare_url`.
    pub token: String,
    /// SHA-256 of the encrypted block as listed by the API; empty if not listed.
    pub hash_digest: Vec<u8>,
    /// Plaintext size claimed by the uploader in the revision's `Common.BlockSizes`.
    pub plain_size: Option<u32>,
}

/// A byte range inside one block, as returned by [`BlockMap::blocks_for_range`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSlice {
    /// One-based block index.
    pub index: i32,
    /// Start offset inside the block's plaintext.
    pub start: u64,
    /// End offset (exclusive) inside the block's plaintext.
    pub end: u64,
}

/// The block list of one revision, with what is needed to download and verify
/// any block on its own.
///
/// Build it with [`ProtonDriveClient::get_block_map`] and download blocks with
/// [`ProtonDriveClient::download_block`]. Each downloaded block's hash is
/// checked. The revision manifest signature covers all blocks, so it is not
/// verified by single-block reads; use `FileDownloader::download_to_stream`
/// for an authenticated full download. The node key is therefore not kept.
#[derive(Clone)]
pub struct BlockMap {
    /// The revision the blocks belong to.
    pub revision_uid: RevisionUid,
    /// Session key that decrypts the blocks.
    pub content_key: PgpSessionKey,
    /// Blocks in index order, starting at index 1 without gaps.
    pub blocks: Vec<BlockMapEntry>,
}

impl std::fmt::Debug for BlockMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockMap")
            .field("revision_uid", &self.revision_uid)
            .field("content_key", &"<redacted>")
            .field("blocks", &self.blocks)
            .finish()
    }
}

impl BlockMap {
    /// Builds a map from a complete, contiguous block listing (as returned by
    /// [`crate::node::download::list_all_blocks`]) and optional claimed plaintext
    /// sizes in block order.
    ///
    /// Sizes are ignored, with a warning, unless there is exactly one
    /// non-negative size per block.
    pub fn from_parts(
        revision_uid: RevisionUid,
        content_key: PgpSessionKey,
        blocks: Vec<BlockDto>,
        claimed_block_sizes: Option<&[i32]>,
    ) -> Self {
        let sizes: Option<Vec<u32>> = claimed_block_sizes.and_then(|sizes| {
            let converted: Option<Vec<u32>> =
                sizes.iter().map(|size| u32::try_from(*size).ok()).collect();
            match converted {
                Some(converted) if converted.len() == blocks.len() => Some(converted),
                _ => {
                    log::warn!(
                        "Ignoring claimed block sizes of revision {}: {} sizes for {} blocks",
                        revision_uid,
                        sizes.len(),
                        blocks.len()
                    );
                    None
                }
            }
        });

        let blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(position, block)| BlockMapEntry {
                index: block.index,
                bare_url: block.bare_url,
                token: block.token,
                hash_digest: block.hash_digest,
                plain_size: sizes.as_ref().map(|sizes| sizes[position]),
            })
            .collect();

        Self {
            revision_uid,
            content_key,
            blocks,
        }
    }

    /// Number of blocks.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// `true` for a revision without content blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The entry for a one-based block index.
    pub fn entry(&self, index: i32) -> Option<&BlockMapEntry> {
        let position = usize::try_from(index.checked_sub(1)?).ok()?;
        self.blocks
            .get(position)
            .filter(|entry| entry.index == index)
    }

    /// Claimed plaintext sizes of all blocks, or `None` if any is unknown.
    pub fn plain_sizes(&self) -> Option<Vec<u32>> {
        self.blocks.iter().map(|entry| entry.plain_size).collect()
    }

    /// Claimed plaintext size of the whole revision, if every block size is known.
    pub fn total_plain_size(&self) -> Option<u64> {
        self.blocks
            .iter()
            .map(|entry| entry.plain_size.map(u64::from))
            .sum()
    }

    /// Maps a plaintext byte offset to `(block index, offset within that block)`.
    ///
    /// Fails when block sizes are unknown or when `offset` is at or past the end
    /// of the file.
    pub fn locate(&self, offset: u64) -> anyhow::Result<(i32, u64)> {
        let sizes = self.known_sizes()?;
        let mut block_start = 0u64;
        for (entry, size) in self.blocks.iter().zip(sizes) {
            let block_end = block_start + u64::from(size);
            if offset < block_end {
                return Ok((entry.index, offset - block_start));
            }
            block_start = block_end;
        }
        anyhow::bail!("offset {offset} is out of range for file of {block_start} bytes")
    }

    /// The block slices that cover `[offset, offset + length)`, clipped to the end
    /// of the file. Empty when `length` is 0 or `offset` is at or past the end.
    ///
    /// Fails when block sizes are unknown.
    pub fn blocks_for_range(&self, offset: u64, length: u64) -> anyhow::Result<Vec<BlockSlice>> {
        let sizes = self.known_sizes()?;
        let end = offset.saturating_add(length);
        let mut slices = Vec::new();
        let mut block_start = 0u64;
        for (entry, size) in self.blocks.iter().zip(sizes) {
            let block_end = block_start + u64::from(size);
            if block_start >= end {
                break;
            }
            if block_end > offset {
                slices.push(BlockSlice {
                    index: entry.index,
                    start: offset.saturating_sub(block_start),
                    end: end.min(block_end) - block_start,
                });
            }
            block_start = block_end;
        }
        Ok(slices)
    }

    /// Replaces URLs and tokens with those of a fresh, complete block listing.
    ///
    /// The listing must have the same block indices and hashes as the map.
    pub fn apply_refreshed_blocks(&mut self, blocks: Vec<BlockDto>) -> anyhow::Result<()> {
        anyhow::ensure!(
            blocks.len() == self.blocks.len(),
            "refreshed listing of revision {} has {} blocks, expected {}",
            self.revision_uid,
            blocks.len(),
            self.blocks.len()
        );
        for (entry, block) in self.blocks.iter().zip(&blocks) {
            anyhow::ensure!(
                entry.index == block.index && entry.hash_digest == block.hash_digest,
                "refreshed listing of revision {} differs at block #{}",
                self.revision_uid,
                entry.index
            );
        }
        for (entry, block) in self.blocks.iter_mut().zip(blocks) {
            entry.bare_url = block.bare_url;
            entry.token = block.token;
        }
        Ok(())
    }

    /// Lists the revision again and stores fresh URLs and tokens for every block.
    pub async fn refresh_urls(&mut self, client: &ProtonDriveClient) -> anyhow::Result<()> {
        let revision =
            RevisionOperations::get_revision_with_all_blocks(client, &self.revision_uid).await?;
        self.apply_refreshed_blocks(revision.blocks)
    }

    fn known_sizes(&self) -> anyhow::Result<Vec<u32>> {
        self.plain_sizes().ok_or_else(|| {
            anyhow::anyhow!("revision {} has no claimed block sizes", self.revision_uid)
        })
    }
}

/// Decrypts a revision's extended attributes and returns `Common.BlockSizes`, or
/// `None` when the attributes do not declare them.
pub(crate) async fn decrypt_claimed_block_sizes(
    client: &ProtonDriveClient,
    node_uid: &NodeUid,
    revision: &crate::api::revision::RevisionDto,
    extended_attributes: &PgpArmoredMessage,
    node_key: &PgpPrivateKey,
) -> anyhow::Result<Option<Vec<i32>>> {
    use crate::api::attr::ExtendedAttributes;
    use crate::author::Author;
    use crate::node::authorship::AuthorshipClaim;

    let metric_item = crate::telemetry::MetricItem::from_revision(node_uid, revision);
    let claim = AuthorshipClaim {
        keys: vec![],
        author: Author::ANONYMOUS,
        key_retrieval_error_message: None,
    };
    let (bytes, _, _) = client
        .integrity_reporter()
        .decrypt_message(
            client,
            &metric_item,
            "nodeExtendedAttributes",
            extended_attributes,
            None,
            [node_key],
            &claim,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let xattr: ExtendedAttributes = serde_json::from_slice(&bytes)?;
    Ok(xattr
        .common
        .and_then(|common| common.block_sizes)
        .filter(|sizes| !sizes.is_empty()))
}

/// Reads `Common.BlockSizes` from the revision as listed by `get_revisions`.
pub(crate) async fn listed_claimed_block_sizes(
    client: &ProtonDriveClient,
    revision_uid: &RevisionUid,
    node_key: &PgpPrivateKey,
) -> anyhow::Result<Option<Vec<i32>>> {
    let response = client
        .api()
        .files()
        .get_revisions(
            revision_uid.node_uid.volume_id.clone(),
            revision_uid.node_uid.link_id.clone(),
        )
        .await?;
    let revision = response
        .revisions
        .into_iter()
        .find(|revision| revision.id == revision_uid.revision_id)
        .ok_or_else(|| anyhow::anyhow!("revision not found"))?;
    let Some(xattr) = revision.extended_attributes.as_ref() else {
        return Ok(None);
    };
    decrypt_claimed_block_sizes(client, &revision_uid.node_uid, &revision, xattr, node_key).await
}

impl ProtonDriveClient {
    /// Builds a [`BlockMap`] for a revision: the complete block list (paged), the
    /// content key and, when available, the claimed plaintext block sizes from the
    /// revision's extended attributes.
    ///
    /// Sizes come from the XAttr of the revision response, or from the revision
    /// listing when that response has none. They are left unknown when the
    /// revision does not declare them or its extended attributes cannot be
    /// decrypted.
    pub async fn get_block_map(&self, revision_uid: RevisionUid) -> anyhow::Result<BlockMap> {
        let secrets =
            crate::node::file::FileOperations::get_secrets(self, revision_uid.node_uid.clone())
                .await?;
        let revision =
            RevisionOperations::get_revision_with_all_blocks(self, &revision_uid).await?;

        let sizes = match revision.revision.extended_attributes.as_ref() {
            Some(xattr) => {
                decrypt_claimed_block_sizes(
                    self,
                    &revision_uid.node_uid,
                    &revision.revision,
                    xattr,
                    &secrets.base.key,
                )
                .await
            }
            // Fall back to the revision listing, which FileDownloader::claimed_block_sizes
            // has always used.
            None => listed_claimed_block_sizes(self, &revision_uid, &secrets.base.key).await,
        }
        .unwrap_or_else(|error| {
            log::warn!(
                "Cannot read claimed block sizes of revision {}: {:#}",
                revision_uid,
                error
            );
            None
        });

        Ok(BlockMap::from_parts(
            revision_uid,
            secrets.content_key,
            revision.blocks,
            sizes.as_deref(),
        ))
    }

    /// Downloads, verifies and decrypts one block of a [`BlockMap`].
    ///
    /// The SHA-256 of the encrypted block must match the listed hash, otherwise
    /// this fails with [`crate::node::download::DataIntegrityException`]. An
    /// expired URL is refreshed for this call through the block downloader; the
    /// map itself is not changed (see [`BlockMap::refresh_urls`]). When the
    /// block's plaintext size is known, the decrypted size must match it.
    pub async fn download_block(&self, map: &BlockMap, index: i32) -> anyhow::Result<Vec<u8>> {
        let entry = map.entry(index).ok_or_else(|| {
            anyhow::anyhow!(
                "block index {index} out of range for revision {} with {} blocks",
                map.revision_uid,
                map.len()
            )
        })?;
        let mut data = Vec::new();
        self.block_downloader()
            .download_verified(
                self,
                map.revision_uid.clone(),
                index,
                entry.bare_url.clone(),
                entry.token.clone(),
                &entry.hash_digest,
                map.content_key.clone(),
                &mut data,
            )
            .await?;
        if let Some(size) = entry.plain_size {
            anyhow::ensure!(
                data.len() as u64 == u64::from(size),
                "block #{index} of revision {} decrypted to {} bytes, claimed {size}",
                map.revision_uid,
                data.len()
            );
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoGenerator;

    fn block(index: i32) -> BlockDto {
        BlockDto {
            index,
            hash_digest: vec![index as u8; 32],
            bare_url: format!("https://storage.test/{index}"),
            token: format!("token-{index}"),
        }
    }

    fn map(sizes: Option<&[i32]>, count: i32) -> BlockMap {
        BlockMap::from_parts(
            RevisionUid::default(),
            CryptoGenerator::generate_session_key(),
            (1..=count).map(block).collect(),
            sizes,
        )
    }

    #[test]
    fn offsets_map_to_blocks_with_uniform_sizes() {
        let map = map(Some(&[4, 4, 4]), 3);

        assert_eq!(map.locate(0).unwrap(), (1, 0));
        assert_eq!(map.locate(3).unwrap(), (1, 3));
        assert_eq!(map.locate(4).unwrap(), (2, 0));
        assert_eq!(map.locate(11).unwrap(), (3, 3));
        assert_eq!(map.total_plain_size(), Some(12));
    }

    #[test]
    fn offsets_map_to_blocks_with_non_uniform_sizes() {
        let map = map(Some(&[10, 3, 7]), 3);

        assert_eq!(map.locate(9).unwrap(), (1, 9));
        assert_eq!(map.locate(10).unwrap(), (2, 0));
        assert_eq!(map.locate(12).unwrap(), (2, 2));
        assert_eq!(map.locate(13).unwrap(), (3, 0));
        assert_eq!(map.locate(19).unwrap(), (3, 6));
    }

    #[test]
    fn offset_at_or_past_end_is_out_of_range() {
        let map = map(Some(&[10, 3, 7]), 3);

        let error = map.locate(20).unwrap_err();
        assert!(error.to_string().contains("out of range"), "{error}");
        assert!(map.locate(u64::MAX).is_err());
    }

    #[test]
    fn offsets_need_known_sizes() {
        assert!(map(None, 2).locate(0).is_err());
        assert!(map(None, 2).blocks_for_range(0, 1).is_err());
        assert_eq!(map(None, 2).total_plain_size(), None);
    }

    #[test]
    fn mismatched_or_negative_sizes_are_ignored() {
        assert_eq!(map(Some(&[4, 4]), 3).plain_sizes(), None);
        assert_eq!(map(Some(&[4, -1]), 2).plain_sizes(), None);
        assert_eq!(map(Some(&[4, 2]), 2).plain_sizes(), Some(vec![4, 2]));
    }

    #[test]
    fn range_spanning_blocks_is_split_into_slices() {
        let map = map(Some(&[10, 3, 7]), 3);

        assert_eq!(
            map.blocks_for_range(8, 6).unwrap(),
            vec![
                BlockSlice {
                    index: 1,
                    start: 8,
                    end: 10
                },
                BlockSlice {
                    index: 2,
                    start: 0,
                    end: 3
                },
                BlockSlice {
                    index: 3,
                    start: 0,
                    end: 1
                },
            ]
        );
    }

    #[test]
    fn range_is_clipped_to_end_of_file() {
        let map = map(Some(&[10, 3]), 2);

        assert_eq!(
            map.blocks_for_range(11, 100).unwrap(),
            vec![BlockSlice {
                index: 2,
                start: 1,
                end: 3
            }]
        );
        assert!(map.blocks_for_range(13, 5).unwrap().is_empty());
        assert!(map.blocks_for_range(0, 0).unwrap().is_empty());
    }

    #[test]
    fn entries_are_found_by_one_based_index() {
        let map = map(None, 3);

        assert_eq!(map.entry(1).unwrap().token, "token-1");
        assert_eq!(map.entry(3).unwrap().bare_url, "https://storage.test/3");
        assert!(map.entry(0).is_none());
        assert!(map.entry(4).is_none());
        assert!(map.entry(-1).is_none());
    }

    #[test]
    fn refreshed_listing_replaces_urls_and_tokens() {
        let mut map = map(Some(&[1, 1]), 2);
        let refreshed: Vec<_> = (1..=2)
            .map(|index| BlockDto {
                bare_url: format!("https://fresh.test/{index}"),
                token: format!("fresh-{index}"),
                ..block(index)
            })
            .collect();

        map.apply_refreshed_blocks(refreshed).unwrap();

        assert_eq!(map.entry(2).unwrap().bare_url, "https://fresh.test/2");
        assert_eq!(map.entry(2).unwrap().token, "fresh-2");
        assert_eq!(map.entry(2).unwrap().plain_size, Some(1));
    }

    #[test]
    fn refreshed_listing_with_other_blocks_is_rejected() {
        let mut map = map(None, 2);

        assert!(map.apply_refreshed_blocks(vec![block(1)]).is_err());
        let changed = vec![
            block(1),
            BlockDto {
                hash_digest: vec![0; 32],
                ..block(2)
            },
        ];
        assert!(map.apply_refreshed_blocks(changed).is_err());
        assert_eq!(map.entry(1).unwrap().token, "token-1");
    }

    #[test]
    fn debug_output_redacts_the_content_key() {
        let output = format!("{:?}", map(None, 1));
        assert!(output.contains("<redacted>"));
        assert!(!output.contains("key: ["));
    }
}
