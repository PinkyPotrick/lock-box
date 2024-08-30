package com.lockbox.blockchain;

import java.util.ArrayList;
import java.util.List;

public class Blockchain {
    private List<Block> chain;

    public Blockchain() {
        this.chain = new ArrayList<>();
        // Add the genesis block
        this.chain.add(new Block(0, "Genesis Block", "0"));
    }

    public Block getLatestBlock() {
        return this.chain.get(this.chain.size() - 1);
    }

    public void addBlock(String data) {
        Block previousBlock = getLatestBlock();
        Block newBlock = new Block(previousBlock.getId() + 1, data, previousBlock.getHash());
        this.chain.add(newBlock);
    }

    public boolean isChainValid() {
        for (int i = 1; i < this.chain.size(); i++) {
            Block currentBlock = this.chain.get(i);
            Block previousBlock = this.chain.get(i - 1);
            if (!currentBlock.getHash().equals(currentBlock.generateHash())) {
                return false;
            }
            if (!currentBlock.getPreviousHash().equals(previousBlock.getHash())) {
                return false;
            }
        }
        return true;
    }

    public List<Block> getChain() {
        return chain;
    }

    public void setChain(List<Block> chain) {
        this.chain = chain;
    }
}