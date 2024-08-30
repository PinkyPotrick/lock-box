package com.lockbox.blockchain;

import com.lockbox.utils.AppConstants;

public class Miner {
    
    private double reward;    

    public void mine(Block block, Blockchain blockchain) {  

        while(notGoldenHash(block)) {
            //generating the block hash
            block.generateHash();
            block.incrementNonce();
        }
  
        System.out.println(block + " has just mined...");
        System.out.println("Hash is: " + block.getHash());
        //appending the block to the blockchain
        blockchain.addBlock(block.getData());  
        //calculating the reward
        reward += AppConstants.MINER_REWARD;
    }  
      
    // So miners will generate hash values until they find the right hash.
    //that matches with DIFFICULTY variable declared in class Constants
    public boolean notGoldenHash(Block block) {  
        String leadingZeros = new String(new char[AppConstants.DIFFICULTY]).replace('\0', '0');  
        return !block.getHash().substring (0, AppConstants.DIFFICULTY).equals (leadingZeros);  
    }

    public double getReward() {  
        return this.reward;  
    }  
}
