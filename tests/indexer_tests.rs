use fixtures::ctx::E2ECtx;
use tracing::info;

use anyhow::Result;

mod fixtures;

mod e2e_indexer {
    use hyle::model::indexer::BlockDb;

    use super::*;

    async fn scenario_indexer(ctx: E2ECtx) -> Result<()> {
        ctx.wait_height(5).await?;

        info!("➡️  Querying block at height 5");
        let start_block = ctx
            .indexer_client()
            .query_indexer("indexer/block/height/5")
            .await?
            .json::<BlockDb>()
            .await?;

        assert_eq!(start_block.height, 5);
        info!("➡️  Start block: {:?}", start_block);
        let mut block = start_block;

        while block.height != 0 {
            info!("➡️  Querying block by hash at height {}", block.height - 1);

            let parent_block = ctx
                .indexer_client()
                .query_indexer(&format!("indexer/block/hash/{}", block.parent_hash.0))
                .await?;

            let parent_block = parent_block.json::<BlockDb>().await?;

            info!("➡️  Parent block: {:?}", parent_block);
            assert_eq!(parent_block.height, block.height - 1);

            block = parent_block;
        }

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn indexer_multi_nodes() -> Result<()> {
        let ctx = E2ECtx::new_multi_with_indexer(2, 500).await?;
        scenario_indexer(ctx).await
    }
}
