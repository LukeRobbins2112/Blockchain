
////////////////////////////////////////////////////////////////////////////////////

// @TODO 

/*
    * Begin implementing block verification
        * Perform work
    * Create actual block chain from newly-verified blocks
        * Make sure there are no duplicates, and check timestamp/length
        * Add blocks to the beginning
    * Multicast updated Ledger *** UN-COMMENT multicastLedger() call in BlockVerifier method
*/

// @DONE

/*
    * Separate the Block struct from the BlockRecord struct - Block struct has inner BlockRecord struct(s)
        * Allows you to then create a hash from the BlockRecord struct and put that into Block header
            * Unsigned hash, signed hash
    * Add custom comparator for PriorityQueue, for ordering Block objects by timestamp
        * Un-marshal Blocks then use timestamp for ordering
    * Test new marshalling with BlockRecord as inner variable of Block
    * Add Timestamp field to Block
    * Implement hash and signed hash for unverified blocks
    * Set up client/server connection for transmitting newly-created unverified blocks
     * Set up recipient for newly-created unverified blocks
        * Push unverified blocks onto priority queue
*/


////////////////////////////////////////////////////////////////////////////////////



/* XML facilities */
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/* Security and cryptography */
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;

import java.security.MessageDigest; // To produce the SHA-256 hash.


/* General facilities */
import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.text.*;


// **********************************************************************************
// Ledger - aka Blockchain - contains list of Blocks (can be marshalled as a whole)
// Block "struct", containing all the XML fields and methods
// BlockRecord struct, to be hashed for Block verification
// Block comparator, for processing Blocks in order by Timestamp
// **********************************************************************************

@XmlRootElement
class Ledger{

    public LinkedList<Block> chain;

    public Ledger(){
        this.chain = new LinkedList<Block>();

         // Initial "dummy" block
        Block dummy = new Block();
        dummy.setABlockID("dummy");
        dummy.blockRecord.setBlockNumber("1");
        String brMarshal = BlockMarshaller.marshalBlockRecord(dummy);
        String brHash = BlockMarshaller.hashData(brMarshal);
        dummy.setASHA256String(brHash);
        this.chain.addFirst(dummy);
    }

    public void add(Block b){
        this.chain.addFirst(b);
    }

    public int size(){
        return this.chain.size();
    }

    public boolean containsID(String blockID){

        for (Block b : this.chain){
            if (b.getABlockID().equals(blockID)){
                return true;
            }
        }

        return false;
    }

    public Block frontBlock(){
        return this.chain.peek();
    }

    public String prevHash(){
        return this.chain.peek().getASHA256String();
    }

    public String prevBlockNum(){
        return this.chain.peek().blockRecord.getBlockNumber();
    }

}

@XmlRootElement
class Block{

    // Block Information
    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String CreatingProcess;
    String PreviousHash;
    String Timestamp;

    // BlockRecord Data
    BlockRecord blockRecord;

    // Constructor
    public Block(){
        this.blockRecord = new BlockRecord();
    }


    // Setters and getters for Block header

    public String getASHA256String() {return SHA256String;}
    @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}

    public String getASignedSHA256() {return SignedSHA256;}
    @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

    public String getABlockID() {return BlockID;}
    @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}

    public String getACreatingProcess() {return CreatingProcess;}
    @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

    public String getAPreviousHash() {return PreviousHash;}
    @XmlElement
    public void setAPreviousHash(String PH){this.PreviousHash = PH;}

    public String getTimestamp() {return Timestamp;}
    @XmlElement
    public void setTimestamp(String TS){this.Timestamp = TS;}

    // Setter/Getter for BlockRecord

    public BlockRecord getBlockRecord() {return blockRecord;}
    @XmlElement
    public void setBlockRecord(BlockRecord BR){
        
        this.blockRecord.Fname = BR.getFFname();
        this.blockRecord.Lname = BR.getFLname();
        this.blockRecord.SSNum = BR.getFSSNum();
        this.blockRecord.DOB = BR.getFDOB();
        this.blockRecord.Diag = BR.getGDiag();
        this.blockRecord.Treat = BR.getGTreat();
        this.blockRecord.Rx = BR.getGRx();
    }


}

// POJO for packing into Block struct
@XmlRootElement
class BlockRecord {
 
    // Data fields
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;

    // Validation fields
    String VerificationProcessID;
    String blockNumber = "-1";
    String seedString = "";

    public BlockRecord(){

    }

    public String getFFname() {return Fname;}
    @XmlElement
    public void setFFname(String FN){this.Fname = FN;}

    public String getFLname() {return Lname;}
    @XmlElement
    public void setFLname(String LN){this.Lname = LN;}

    public String getFSSNum() {return SSNum;}
    @XmlElement
    public void setFSSNum(String SS){this.SSNum = SS;}
  
    public String getFDOB() {return DOB;}
    @XmlElement
    public void setFDOB(String DOB){this.DOB = DOB;}

    public String getGDiag() {return Diag;}
    @XmlElement
    public void setGDiag(String D){this.Diag = D;}

    public String getGTreat() {return Treat;}
    @XmlElement
    public void setGTreat(String D){this.Treat = D;}

    public String getGRx() {return Rx;}
    @XmlElement
    public void setGRx(String D){this.Rx = D;}

    // Hash data
    public String getSeedString() {return seedString;}
    @XmlElement
    public void setSeedString(String sStr){this.seedString = sStr;}

    public String getBlockNumber() {return blockNumber;}
    @XmlElement
    public void setBlockNumber(String BN){this.blockNumber = BN;}

    public String getAVerificationProcessID() {return VerificationProcessID;}
    @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

}

class BlockComparator implements Comparator<Block>{

    @Override
    public int compare(Block b1, Block b2){
        return (b1.getTimestamp().compareTo(b2.getTimestamp()));
    }

}

// **********************************************************************************
// Used to generate public/private keys, create hashes, etc.
// **********************************************************************************
class BlockMarshaller{

    public BlockMarshaller(){

    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {

        // Create object used to apply a digital signature, using the algorithm specified: SHA1 with RSA
        Signature signer = Signature.getInstance("SHA1withRSA");

        // Initializes signing object (signer) with our private key; it says which key to use when signing data

        // Sign the 
        signer.initSign(key);

        // Feeds in the data to the signer object
        // At this point, we basically just passed over a copy of the data and the key to the signer object
        // We haven't yet applied the signature to the data, within the signer object
        signer.update(data);

        // Applies the signature to the data and returns the result
        return (signer.sign());
  }

  public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {

        // Creates a signature object, which will verify the signature using the algorithm specified
        Signature signer = Signature.getInstance("SHA1withRSA");

        // Just passes the public key to the signature object; signer will use key to decrypt any signed messages
        signer.initVerify(key);

        // Passes the signed data to the signer object, but does not yet apply the public key
        signer.update(data);

        // Returns true if the signature is verified
        // The way it does this is :
            // Signer creates its own hash of the raw data bytes
            // Signer decrypts sig with the public key
            // The signature is also just the hash of the raw data, but with the private key applied
                // If the decrypted hash matches the hash performed by signer, then the signature is verified
        return (signer.verify(sig));
  }

  public static KeyPair generateKeyPair(long seed){

        try{
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
            rng.setSeed(seed);
            keyGenerator.initialize(1024, rng);

            return (keyGenerator.generateKeyPair());
        }
        catch (Exception e){
            e.printStackTrace();
        }

        return null;
  }

  public static String marshalBlockRecord(Block block){

    String stringXML = null;

    try{
        /* The XML conversion tools: */
        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // CDE Make the output pretty printed:
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        /* CDE We marshal the block object into an XML string so it can be sent over the network: */
        jaxbMarshaller.marshal(block.blockRecord, sw);
        stringXML = sw.toString();
        // System.out.println(stringXML);
    } catch(Exception e){
        e.printStackTrace();
    }
    

    return stringXML;
  }

  public static String marshalBlock(Block block){

    String stringXML = null;

    try{

        // If kill signal sent, send indication to receiving thread
        if (block.getABlockID().equals("NO_RECORDS_REMAINING")) return "NO_RECORDS_REMAINING";
        
        // Marshal block to XML
        JAXBContext jaxbContext = JAXBContext.newInstance(Block.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // CDE Make the output pretty printed:
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        /* CDE We marshal the block object into an XML string so it can be sent over the network: */
        jaxbMarshaller.marshal(block, sw);
        stringXML = sw.toString();
        // System.out.println(stringXML);
    } catch(Exception e){
        e.printStackTrace();
    }

    return stringXML;
  }

  public static Block unmarshalBlock(String blockXML){

    try{
        JAXBContext jaxbContext = JAXBContext.newInstance(Block.class);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        StringReader reader = new StringReader(blockXML);
        // System.out.println(blockXML);

        // Re-create the block 
        Block block = (Block) jaxbUnmarshaller.unmarshal(reader);
        return block;
        
    } catch(Exception e){
        e.printStackTrace();
    }
    
    return null;
  }

  public static String marshalLedger(){

    String stringXML = null;

    try{
        
        // Marshal block to XML
        JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // Format the output
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        // Marshal the entire blockchain into XML
        jaxbMarshaller.marshal(Blockchain.LEDGER, sw);
        stringXML = sw.toString();
        // System.out.println(stringXML);
    } catch(Exception e){
        e.printStackTrace();
    }

    return stringXML;
    
  }

  public static Ledger unmarshalLedger(String blockchainXML){

    try{
        JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        StringReader reader = new StringReader(blockchainXML);
        // System.out.println(blockchainXML);

        // Re-create the block 
        Ledger blockChain = (Ledger) jaxbUnmarshaller.unmarshal(reader);
        return blockChain;
        
    } catch(Exception e){
        e.printStackTrace();
    }
    
    return null;
  }

  public static String hashData(String data){

    try{
        /* Create the SHA-256 hash of the block: */
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update (data.getBytes());
        byte byteData[] = md.digest();

        // Create hex representation of byte data
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
        sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }

        String SHA256String = sb.toString();
        return SHA256String;
    } catch(Exception e){
        e.printStackTrace();
    }
      
    return null;
  }

  public static String signDataString(String unsignedData){

    try{
        // Sign the hash of the BlockRecord data using the private key generated
        byte[] digitalSignature = signData(unsignedData.getBytes(), Blockchain.keyPair.getPrivate());
        
        // Verify the signature, using the public key generated
        boolean verified = verifySig(unsignedData.getBytes(), Blockchain.keyPair.getPublic(), digitalSignature);
        //System.out.println("Has the signature been verified: " + verified + "\n");
        
        //System.out.println("Original SHA256 Hash: " + unsignedData + "\n");

        /* Add the SHA256String to the header for the block. We turn the byte[] signature into a string so that it can be placed into
        the block, but also show how to return the string to a byte[], which you'll need if you want to use it later.*/

        // Get the String representation of the digital signature created from the private key + BlockRecord hash
        String signedData = Base64.getEncoder().encodeToString(digitalSignature);
        //System.out.println("The signed SHA-256 string: " + signedData + "\n");

        // Re-encode the string digital signature into bytes to test that it can still be used for verification
        byte[] testSignature = Base64.getDecoder().decode(signedData);
        //System.out.println("Testing restore of signature: " + Arrays.equals(testSignature, digitalSignature));

        // Re-verify the restored signature
        // Take the un-signed, original hash of the data (SHA256String), decrypt testSignature using the public key, then compare
        verified = verifySig(unsignedData.getBytes(), Blockchain.keyPair.getPublic(), testSignature);
        //System.out.println("Has the restored signature been verified: " + verified + "\n");

        return signedData;
    } catch (Exception e){
        e.printStackTrace();
    }

        return null;
  }

}

// **********************************************************************************
// Used for port lookups
// **********************************************************************************
class Ports{
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;
  
    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;
  
    public void setPorts(){
      KeyServerPort = KeyServerPortBase + (Blockchain.PID);
      UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID);
      BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID);
    }
}

// **********************************************************************************
// Produces new unverified blocks from file and multicasts them out
// **********************************************************************************

class NewBlockCreator extends Thread{

    private static String fileName;
    int pnum;

    // Indices used for parsing input fields
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    public NewBlockCreator(){
        this.pnum = Blockchain.PID;
        fileName = "BlockInput" + Integer.toString(Blockchain.PID) + ".txt";
    }

    public BlockRecord createBlockRecord(String input){
            
        // Create a new, empty Block array
        BlockRecord blockRecord = new BlockRecord();
            
        // Build the BlockRecord for the current block
        String [] tokens = input.split(" "); 
                
        String ss = tokens[iSSNUM];
        blockRecord.setFSSNum(ss);
        blockRecord.setFFname(tokens[iFNAME]);
        blockRecord.setFLname(tokens[iLNAME]);
        blockRecord.setFDOB(tokens[iDOB]);
        blockRecord.setGDiag(tokens[iDIAG]);
        blockRecord.setGTreat(tokens[iTREAT]);
        blockRecord.setGRx(tokens[iRX]);

        return blockRecord;

    }

    public void hashAndSignBlockRecord(Block block){

        String marshalledBlockRecord = BlockMarshaller.marshalBlockRecord(block);
        String blockRecordHash = BlockMarshaller.hashData(marshalledBlockRecord);
        String signedBlockRecordHash = BlockMarshaller.signDataString(blockRecordHash);

        // Insert the un-signed hash (@TODO call a hash on the raw data for this)
        block.setASHA256String(blockRecordHash);
            
        // Insert the signed hash, using the private key and entry data 
        // (@TODO get the hash above, and sign it using the java.security.Signature class as shown in BlockH.java)
        block.setASignedSHA256(signedBlockRecordHash);

    }

    public Block createBlock(BlockRecord blockRecord){

        // Create a new, empty Block array
        Block newBlock = new Block();

        // Add full BlockRecord to current Block
        newBlock.setBlockRecord(blockRecord);

        // Fill the Block header //

        /* CDE: Generate a unique blockID. This would also be signed by creating process: */
        // idA = UUID.randomUUID();
        String suuid = new String(UUID.randomUUID().toString());
        newBlock.setABlockID(suuid);
        newBlock.setACreatingProcess("Process:" + Integer.toString(pnum));

        // @TODO sign the blockID and include here
        // To be set later, once the block is verified
        newBlock.blockRecord.setAVerificationProcessID("-1");

        // Create SHA256 hash, and signed version; insert those into Block header
        hashAndSignBlockRecord(newBlock);
            
        // Finally, add a timestamp at the new Block's creation
        String T1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
            
        // Add the processID to the end of the timestamp so we don't have collisions (if 2 identical timestamps)
        String TimeStampString = T1 + "." + pnum + "\n";
        newBlock.setTimestamp(TimeStampString);

        return newBlock;
    }

    public void marshalAndMulticast(Block block){

        // Get String of marshalled unverified Block to multicast
        String marshalledBlock = BlockMarshaller.marshalBlock(block);

        // Multicast Block

        Socket sock;
        PrintStream toServer;

        try{

            // Send a sample unverified block to each server
            for(int i=0; i < Blockchain.numProcesses; i++){
                sock = new Socket(Blockchain.serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(marshalledBlock);
                toServer.flush();
                sock.close();
            }

        }catch (Exception x) {
            x.printStackTrace ();
        }

    }

    public ArrayList<Block> createBlocks(){

        try{
            BufferedReader br = new BufferedReader(new FileReader(fileName));
            String input;

            // @TODO for now using a fixed number of block records
            ArrayList<Block> blockArrayList = new ArrayList<Block>();
            

            while ((input = br.readLine()) != null){

                // Create a new, empty Block array
                BlockRecord blockRecord = createBlockRecord(input);
                Block newBlock = createBlock(blockRecord);

                // Add new Block to the list
                blockArrayList.add(newBlock);

                // Multicast new unverified block
                marshalAndMulticast(newBlock);
                
                // Add tiny delay to prevent duplicate Timestamps
                try{Thread.sleep(10);}catch(Exception e){e.printStackTrace();}
            }

            // SEND KILL SIGNAL INDICATING NO MORE RECORDS
            Block killBlock = new Block();
            killBlock.setABlockID("NO_RECORDS_REMAINING");
            marshalAndMulticast(killBlock);
            try{Thread.sleep(1000);}catch(Exception e){e.printStackTrace();}  // Send one more time to break server accept() hang
            marshalAndMulticast(killBlock);

            br.close();
            return blockArrayList;

        } catch(IOException e){
            e.printStackTrace();
        }
        
        return null;
    }

    public void run(){

        ArrayList<Block> newBlocks = createBlocks();
        // System.out.println("Done creating blocks");

    }

}

// **********************************************************************************
// Receives unverified blocks and places them on priority queue to be processed
// **********************************************************************************

class UnverifiedBlockProcessor extends Thread{

    // Threadsafe queue used by UnverifiedBlockProcessor and BlockVerifier
    BlockingQueue<Block> queue;
    boolean blocksRemaining;

    public UnverifiedBlockProcessor(BlockingQueue<Block> _queue){
        this.queue = _queue;
        this.blocksRemaining = true;
    }

    // **************************
    // Inner class
    // **************************
    class BlockProcessor extends Thread{

        Socket sock;

        BlockProcessor (Socket s) {
            sock = s;
        } 

        public void run(){

            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                // Read the full block entry as a marshalled string
                StringBuilder blockString = new StringBuilder();
                String data;
                while((data = in.readLine()) != null){

                    if (data.equals("NO_RECORDS_REMAINING")){
                        UnverifiedBlockProcessor.this.blocksRemaining = false;
                        sock.close();
                        return;
                    }

                    blockString.append(data);
                    blockString.append("\n");
                }

                // @TODO un-marshall String into Block structure
                // Then add block to the priority queue
                Block receivedBlock = BlockMarshaller.unmarshalBlock(blockString.toString());

                // Insert the new un-verified block into the priority queue
                UnverifiedBlockProcessor.this.queue.put(receivedBlock);

                // if (blockString != null) System.out.println("PUSHED UNVERIFIED BLOCK ONTO QUEUE\n");

                sock.close(); 
            } catch (Exception x)
            {
              x.printStackTrace();
            }

        }
        
    }

    public void run(){
            
        int q_len = 6; 
        Socket sock;
    
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
      
            while (blocksRemaining) {
                sock = servsock.accept(); // Got a new unverified block
                new BlockProcessor(sock).start(); // So start a thread to process it.
                // System.out.println("");
            }
        } catch (IOException ioe) 
        {
            System.out.println(ioe);
        }
    }
}

// **********************************************************************************
// The main, coordinating process which manages each of the 
// **********************************************************************************

class BlockVerifier extends Thread{

    BlockingQueue<Block> queue;
    boolean blocksRemaining;
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public BlockVerifier(BlockingQueue<Block> _queue){
        this.queue = _queue;
        this.blocksRemaining = true;
    }

    // Build our random seed string
    public static String randomAlphaNumeric(int count) {

        // Just grab random characters to build String of size count, appending them
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < count; i++) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    public void verifyBlock(Block block){

        // For comparison after each loop - check to make sure the Blockchain wasn't updated
        int    curNumBlocks = Blockchain.LEDGER.size();
        String mostRecentHash = Blockchain.LEDGER.prevHash();
        String mostRecentBlockNum = Blockchain.LEDGER.prevBlockNum();

        try {

            // Guaranteed to not fit criteria until we recalculate in loop
            int workNumber = Integer.parseInt("FFFF",16); 

            // Only have to get previous hash and previous block num once, unless chain is updated
            
                // Get sequential blockNum of most recent Block on chain, add 1
                String prevBlockNum = Blockchain.LEDGER.prevBlockNum();
                String newBlockNum = Integer.toString(Integer.parseInt(prevBlockNum) + 1);
                block.blockRecord.setBlockNumber(newBlockNum);
                
                // Get hash of most recent block on the chain
                String prevBlockHash = Blockchain.LEDGER.prevHash();

            // Add verifying process ID into block - only do once regardless
            block.blockRecord.setAVerificationProcessID(Integer.toString(Blockchain.PID));

            while(workNumber > 20000){

                // Get a new random AlphaNumeric seed string, insert into block
                String randString = randomAlphaNumeric(8); 
                block.blockRecord.setSeedString(randString);

                // Hash the updated block
                String blockData = BlockMarshaller.marshalBlockRecord(block);

                // Finally, combine prev block's hash with block data, and hash that combination
                String testData = prevBlockHash + blockData;
                String testHash = BlockMarshaller.hashData(testData);
                
                // Get the leftmost 4 hex values (leftmost 16 bits) and interpret that value
                workNumber = Integer.parseInt(testHash.substring(0,4),16); 
                // System.out.println("First 16 bits " + testHash.substring(0,4) +": " + workNumber + "\n");

                // If the result meets the critera, we are free to add it to the beginning of the blockchain
                if (workNumber < 20000){
                    // System.out.println("Puzzle solved!");
                    // System.out.println("The seed was: " + randString);
                    addBlockToChain(block);
                    break;
                }

                // Check for blockchain updates
                // If a new block has been added, then abandon this verification effort and start over.
                    // Means resetting the hash and blocknum of most recent block (at front of chain)
                // But first, check to see if one of the newly added blocks is this one; abandon this block if so
                
                int numBlocks = Blockchain.LEDGER.size();
                String ledgerHash = Blockchain.LEDGER.prevHash();
                String ledgerBlockNum = Blockchain.LEDGER.prevBlockNum();

                if (numBlocks != curNumBlocks || !ledgerHash.equals(mostRecentHash) || !ledgerBlockNum.equals(mostRecentBlockNum)){
                    
                    // System.out.println("Blockchain has been updated; abandoning work and re-adding Block to queue");
                    
                    if (Blockchain.LEDGER.frontBlock().getABlockID().equals(block.getABlockID())){
                        // System.out.println("Block was verified by another process - abandon verification here");
                        break;
                    }

                    // Recalculate block number based on updated chain
                    prevBlockNum = Blockchain.LEDGER.prevBlockNum();
                    newBlockNum = Integer.toString(Integer.parseInt(prevBlockNum + 1));
                    block.blockRecord.setBlockNumber(newBlockNum);
                    
                    // Recalculate hash based on updated chain
                    // Don't have to "set" since it's not part of block data
                    prevBlockHash = Blockchain.LEDGER.prevHash();
                }

                // Sleep to give the impression of harder work
                try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}

            }
        }catch(Exception ex) {
            ex.printStackTrace();
        }

    }

    boolean checkBlockUnique(Block block){

        if (Blockchain.LEDGER.containsID(block.getABlockID())){
            return false;
        }

        return true;
    }

    public void addBlockToChain(Block block){
        Blockchain.LEDGER.add(block);
    }

    public void multicastBlockchain(){
        PrintStream toServer;
        Socket sock;

        String blockchainString = BlockMarshaller.marshalLedger();

        try{

            for(int i=0; i < Blockchain.numProcesses; i++){
                sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(blockchainString); 
                toServer.flush(); 
                sock.close();
            }

        } catch (Exception e){
            e.printStackTrace();
        }
        

    }

    public void run(){

        while(blocksRemaining){

            try{
                Block block = this.queue.take();

                // Test to see if we're done
                if (block.getABlockID().equals("NO_RECORDS_REMAINING")){
                    break;
                }

                // Check to see if block is already verified
                boolean blockIsUnique = checkBlockUnique(block);

                // If the block is a new one, add to the beginning of the Blockchain and multicast the updated chain
                if (blockIsUnique == true){

                    // Do work to verify block
                    verifyBlock(block);
                    System.out.print("[Verified Block for " + block.blockRecord.getFFname() + "] -- ");
                    // addBlockToChain(block); // <-- this is done in verifyBlock() if the block meets the threshold
                    // multicastBlockchain();
                }

            }catch(InterruptedException ie) { ie.printStackTrace(); }

        }

    }

}

public class Blockchain {

    static String serverName = "localhost";
    static String blockchain = "[First block]";
    static int numProcesses = 2; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N
    static int PID = 0; // Default PID

    // Create public and private keys for this participant
    static final KeyPair keyPair = BlockMarshaller.generateKeyPair(999);

    // Hashmap to store Block ID's, check for duplicates
    // static HashSet<String> blockIDs = new HashSet<String>();

    // The Blockchain itself - linked list of blocks
    static Ledger LEDGER = new Ledger();

    // Running tests
    static final boolean RUN_TESTS = false;
    public static void Test(BlockingQueue<Block> queue){

        if (RUN_TESTS){

        Block b1 = new Block();
        Block b2 = new Block();
        Block b3 = new Block();

        b1.setABlockID("BLOCK_1");
        b1.setASHA256String("block1_prev_hash");

        b2.setABlockID("BLOCK_2");
        b2.setASHA256String("block2_prev_hash");
        b2.blockRecord.setBlockNumber("3");

        b3.setABlockID("BLOCK_3");
        b3.setASHA256String("block3_prev_hash");
        b3.blockRecord.setBlockNumber("2");

        LEDGER.add(b3);
        LEDGER.add(b2);

        // Validate work function
        BlockVerifier bv = new BlockVerifier(queue);
        bv.verifyBlock(b1);
        bv.addBlockToChain(b1);


        // Validate Ledger marshalling
        String marshalList = BlockMarshaller.marshalLedger();
        Ledger bc = BlockMarshaller.unmarshalLedger(marshalList);
        for (Block b : bc.chain){
            System.out.println(b.getABlockID());
        }

        }
    }

    public static void main(String[] args) throws Exception {

        // Assign Process ID
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);

        // Create thread-safe priority queue for processing unverified blocks -- Priority goes by Block timestamp
        final BlockingQueue<Block> queue = new PriorityBlockingQueue<Block>(5, new BlockComparator()); 

        // Perform port number setup for various Processes
        new Ports().setPorts(); 

        //*********************************************************************************************** */

        // VALIDATE ANY FUNCTIONS / DATA
        Test(queue);

        //*********************************************************************************************** */

        // New thread to process new unverified blocks and insert into priority queue
        new UnverifiedBlockProcessor(queue).start();

        // New thread to start creating blocks
        new NewBlockCreator().start(); 

        // Sleep for a bit to wait for queue to fill
        try{ Thread.sleep(1000); } catch(Exception e){} 

        // New thread to validate blocks and add to Ledger
        new BlockVerifier(queue).start(); 

        System.out.println("Done");

        
    }

}