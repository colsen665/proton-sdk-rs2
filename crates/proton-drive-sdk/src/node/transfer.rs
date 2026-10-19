use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct TransferQueue {
    file_semaphore: Arc<Semaphore>,
    block_semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    max_degree_of_parallelism: usize,
}

impl TransferQueue {
    /// Default number of whole-file transfers that may run at once per queue.
    pub const DEFAULT_MAX_CONCURRENT_FILES: usize = 1;

    /// Creates a queue allowing `max_degree_of_parallelism` concurrent block transfers and
    /// [`Self::DEFAULT_MAX_CONCURRENT_FILES`] concurrent file transfers.
    pub fn new(max_degree_of_parallelism: usize) -> Self {
        Self::with_limits(
            max_degree_of_parallelism,
            Self::DEFAULT_MAX_CONCURRENT_FILES,
        )
    }

    /// Creates a queue allowing `max_degree_of_parallelism` concurrent block transfers and
    /// `max_concurrent_files` concurrent file transfers. Both limits must be greater than zero.
    pub fn with_limits(max_degree_of_parallelism: usize, max_concurrent_files: usize) -> Self {
        assert!(
            max_degree_of_parallelism > 0,
            "transfer parallelism must be greater than zero"
        );
        Self {
            file_semaphore: Self::file_semaphore(max_concurrent_files),
            block_semaphore: Arc::new(Semaphore::new(max_degree_of_parallelism)),
            max_degree_of_parallelism,
        }
    }

    /// Returns a queue that keeps this queue's block capacity (shared with it) and allows
    /// `max_concurrent_files` concurrent file transfers. The limit must be greater than zero.
    pub fn with_max_concurrent_files(self, max_concurrent_files: usize) -> Self {
        Self {
            file_semaphore: Self::file_semaphore(max_concurrent_files),
            ..self
        }
    }

    fn file_semaphore(max_concurrent_files: usize) -> Arc<Semaphore> {
        assert!(
            max_concurrent_files > 0,
            "file transfer concurrency must be greater than zero"
        );
        Arc::new(Semaphore::new(max_concurrent_files))
    }

    pub async fn start_file(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        let permit = self.file_semaphore.clone().acquire_owned().await?;
        Ok(permit)
    }

    pub async fn start_block(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        let permit = self.block_semaphore.clone().acquire_owned().await?;
        Ok(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    #[tokio::test]
    async fn default_queue_runs_one_file_at_a_time() {
        let queue = TransferQueue::new(4);
        let first = queue.start_file().await.unwrap();
        assert!(queue.start_file().now_or_never().is_none());
        drop(first);
        assert!(queue.start_file().now_or_never().is_some());
    }

    #[tokio::test]
    async fn file_limit_of_two_holds_two_permits_and_queues_the_third() {
        let queue = TransferQueue::with_limits(4, 2);
        let first = queue.start_file().await.unwrap();
        let _second = queue.start_file().await.unwrap();

        let third = queue.start_file();
        tokio::pin!(third);
        assert!((&mut third).now_or_never().is_none());

        drop(first);
        assert!(third.now_or_never().is_some());
    }

    #[tokio::test]
    async fn raising_the_file_limit_keeps_the_shared_block_capacity() {
        let queue = TransferQueue::new(1);
        let raised = queue.clone().with_max_concurrent_files(2);
        let _first = raised.start_file().await.unwrap();
        let _second = raised.start_file().await.unwrap();

        let _block = queue.start_block().await.unwrap();
        assert!(raised.block_semaphore.try_acquire().is_err());
    }

    #[test]
    #[should_panic(expected = "file transfer concurrency must be greater than zero")]
    fn rejects_zero_file_concurrency() {
        let _ = TransferQueue::with_limits(1, 0);
    }

    #[tokio::test]
    async fn file_capacity_is_released_with_the_permit() {
        let queue = TransferQueue::new(2);
        let permit = queue.start_file().await.unwrap();
        assert!(queue.file_semaphore.try_acquire().is_err());
        drop(permit);
        assert!(queue.file_semaphore.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn block_capacity_matches_configured_parallelism() {
        let queue = TransferQueue::new(2);
        let first = queue.start_block().await.unwrap();
        let second = queue.start_block().await.unwrap();
        assert!(queue.block_semaphore.try_acquire().is_err());
        drop(first);
        assert!(queue.block_semaphore.try_acquire().is_ok());
        drop(second);
    }

    #[tokio::test]
    async fn cloned_queues_share_capacity() {
        let queue = TransferQueue::new(1);
        let clone = queue.clone();
        let permit = queue.start_block().await.unwrap();
        assert!(clone.block_semaphore.try_acquire().is_err());
        drop(permit);
        assert!(clone.start_block().await.is_ok());
    }

    #[test]
    #[should_panic(expected = "transfer parallelism must be greater than zero")]
    fn rejects_zero_parallelism() {
        let _ = TransferQueue::new(0);
    }
}
