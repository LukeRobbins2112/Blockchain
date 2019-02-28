
/*--------------------------------------------------------

1. Luke Robbins / 2/27/2019

2. Java 1.8

3. Compilation Instructions

> javac Blockchain.java

4. Run Instructions

> java Blockchain
> Enter console commands as desribed by assignment, "quit" to exit

Hit Control-C to end the application

5. List of files needed for running the program.

 a. Blockchain.java
 b. Text file of records

6. Notes:

----------------------------------------------------------*/

////////////////////////////////////////////////////////////////////////////////////

// @TODO 

/*
   
    * Move fields from Block to BlockRecord, to prevent malicious changes to data
    
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
     * Begin implementing block verification
        * Perform work
    * Create actual block chain from newly-verified blocks
        * Make sure there are no duplicates
        * Add blocks to the beginning
    * Multicast updated Ledger
        * When you receive a Ledger, check timestamp and length against current when deciding whether to update
            * If received chain is longer, or timestamp of receive blockchain's head node is earlier than 
                timestamp of current blockchain's head node, replace with received chain
    * Add references to Blockchain.java
    * Implement command line tools for additional utilities
    * Add header to the top of BLockchain.java


*/


////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
/*
// References

http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example
http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html // Reading lines and tokens from a file:
https://www.w3schools.com/xml/xml_validator.asp  // XML validator
https://www.mkyong.com/java/jaxb-hello-world-example/  // XML / Object conversion
https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  //  @author JJ
https://dzone.com/articles/generate-random-alpha-numeric  // by Kunal Bhatia  ·  Aug. 09, 12 · Java Zone
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object


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

import javax.xml.bind.DatatypeConverter;

import java.security.KeyFactory;

/* Security and cryptography */
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.spec.X509EncodedKeySpec;

// To produce the SHA-256 hash
import java.security.MessageDigest; 


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

    @XmlElement(name = "Block")
    public LinkedList<Block> chain;

    public static final String outputFile = "BlockchainLedger.xml";

    public Ledger(){
        this.chain = new LinkedList<Block>();

        // Initial "dummy" block
        // Doesn't really matter what the actual data or hash are
        Block dummy = new Block();
        dummy.setABlockID("dummy");
        dummy.blockRecord.setBlockNumber("0");
        String brMarshal = BlockMarshaller.marshalBlockRecord(dummy);
        String brHash = BlockMarshaller.hashData(brMarshal);
        dummy.setASHA256String(brHash);
        dummy.setACreatingProcess(Integer.toString(Blockchain.PID));
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
        return this.chain.getFirst();
    }

    public String prevHash(){
        return this.chain.getFirst().getASHA256String();
    }

    public String prevBlockNum(){
        return this.chain.getFirst().blockRecord.getBlockNumber();
    }

    public String LedgerString(){
        StringBuilder output = new StringBuilder();

        for (Block b : this.chain){
            String entry = "[Block #" + b.blockRecord.getBlockNumber() + " (" + b.blockRecord.getFFname() + ", " + b.blockRecord.getFLname() + ")] - ";
            output.append(entry);
        }

        return output.toString();
    }

    public String creditString(){
        StringBuilder output = new StringBuilder();

        for (Block b : this.chain){
            String entry = "[Block #" + b.blockRecord.getBlockNumber() + " verified by Process:" + b.blockRecord.getAVerificationProcessID() + "] ";
            output.append(entry);
        }

        return output.toString();
    }

    public String recordList(){

        StringBuilder output = new StringBuilder();

        for (Block b : this.chain){

            if (b.getABlockID().equals("dummy")) continue; // Don't include dummy

            BlockRecord br = b.getBlockRecord();
            String entry = br.getBlockNumber() + ". " + b.getTimestamp() + " " + br.getFFname() + " " + br.getFLname()
                        + (" " + br.getFDOB() + " " + br.getFSSNum() + " " + br.getGDiag() + " " + br.getGRx() + " " + br.getGTreat() + "\n");
            output.append(entry);
        }

        return output.toString();
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

        // For hashing
        this.blockRecord.blockNumber = BR.getBlockNumber();
        this.blockRecord.seedString = BR.getSeedString();
        this.blockRecord.VerificationProcessID = BR.getAVerificationProcessID();
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
    String blockNumber;
    String seedString;

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
        // Initialize Marshaller to use the class type specified
        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // Format the outpur so it looks like proper XML
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        // Actually marshal the specific object into string representation of XML
        jaxbMarshaller.marshal(block.blockRecord, sw);
        stringXML = sw.toString();
        
    } catch(Exception e){
        e.printStackTrace();
    }
    

    return stringXML;
  }

  public static String marshalBlock(Block block){

    String stringXML = null;

    try{

        // If kill signal sent, send indication to receiving thread
        // @TODO not really used; right now the thread just hangs
        if (block.getABlockID().equals("NO_RECORDS_REMAINING")) return "NO_RECORDS_REMAINING";
        
        // Marshal block to XML
        JAXBContext jaxbContext = JAXBContext.newInstance(Block.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // Format output
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        // Marshal to XML
        jaxbMarshaller.marshal(block, sw);
        stringXML = sw.toString();
        
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

  public static String marshalLedger(Ledger ledger){

    String stringXML = null;

    try{
        
        // Marshal block to XML
        JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // Format the output
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        // Marshal the entire blockchain into XML
        jaxbMarshaller.marshal(ledger, sw);
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
        // Apply hashing algorithm to the data
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update (data.getBytes());
        byte byteData[] = md.digest();

        // Create hex representation of byte data - Elliott's method
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

  // This method code comes from BlockH.java
  public static String signDataString(String unsignedData){

    try{
        // Apply this process's private key to the data, so recipients can validate Blocks from this one
        byte[] digitalSignature = signData(unsignedData.getBytes(), Blockchain.keyPair.getPrivate());
        
        // Do a sanity check to make sure this process's public key properly restores data
        boolean verified = verifySig(unsignedData.getBytes(), Blockchain.keyPair.getPublic(), digitalSignature);
        //System.out.println("Has the signature been verified: " + verified + "\n");
        
        //System.out.println("Original SHA256 Hash: " + unsignedData + "\n");

        // Convert the digital signature to a String so we can include it in the Block and multicast
        String signedData = Base64.getEncoder().encodeToString(digitalSignature);
        //System.out.println("The signed SHA-256 string: " + signedData + "\n");

        // Do another sanity check, this time to make sure byte[] can be recovered from signature String
        byte[] testSignature = Base64.getDecoder().decode(signedData);
        //System.out.println("Testing restore of signature: " + Arrays.equals(testSignature, digitalSignature));

        // Using the restored byte array of the signature, double-check to make sure it works with un-signed data
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
// Used Elliott's implementation of static class for easy port setup and lookups
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
// Broadcasts Public Keys to allow for signature verification
// **********************************************************************************

  class PublicKeyServer extends Thread {

    public PublicKeyServer(){

    }

    public static String publicKeyToString(PublicKey pubKey){

        try{
            byte[] data = pubKey.getEncoded();
            String pubKeyHax = Base64.getEncoder().encodeToString(data);
            return pubKeyHax;
        } catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }

    public static PublicKey pubKeyFromString(String input){

        byte[] keyData = Base64.getDecoder().decode(input);

        try{
            X509EncodedKeySpec ks = new X509EncodedKeySpec(keyData);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(ks);
            return publicKey;
        }
        catch (NoSuchAlgorithmException nsae){
            nsae.printStackTrace();
        }
        catch (InvalidKeySpecException ikse){
            ikse.printStackTrace();
        }

        return null;
    }

    //************* */
    // Inner Class
    //************* */
    class PublicKeyWorker extends Thread { // Class definition

        Socket sock; 
        PublicKeyWorker (Socket s) {
            sock = s;
        }

        public void run(){
          try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

            String data = in.readLine ();                       // "Process# PublicKey"
            String[] tokens = data.split(" ");                  // [Process#, PublicKey]
            
            PublicKey receivedKey = pubKeyFromString(tokens[1]);
            Blockchain.publicKeyLookup.put(tokens[0], receivedKey);

            System.out.println("Received public key from " + tokens[0]);
            // System.out.println("Size of lookup is " + Integer.toString(Blockchain.publicKeyLookup.size()));

            if (tokens[0].equals("Process:2")){
                Blockchain.allProcessesRunning = true;
            }

            sock.close(); 
          } catch (IOException x){x.printStackTrace();}
        }
      }
      
    public void run(){

      int q_len = 6;
      Socket sock;

      try{

        ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
        while (true) {
            sock = servsock.accept();
            new PublicKeyWorker(sock).start(); 
        }
      } catch (IOException ioe) {
          System.out.println(ioe);
        }
    }

  }

// **********************************************************************************
// Produces new unverified blocks from file and multicasts them out
// **********************************************************************************

class NewBlockCreator extends Thread{

    private static String fileName;
    int pnum;

    // Indices used for parsing input fields
    // Use same protocol as Elliott for field order & lookup
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

        // Insert the un-signed hash
        block.setASHA256String(blockRecordHash);
            
        // Insert the signed hash, using the private key and entry data 
        block.setASignedSHA256(signedBlockRecordHash);

    }

    public Block createBlock(BlockRecord blockRecord){

        // Create a new, empty Block array
        Block newBlock = new Block();

        // Add full BlockRecord to current Block
        newBlock.setBlockRecord(blockRecord);

        // Fill the Block header //

        // @TODO sign the blockID and include here
        // Create a unique blockID, include signed and unsigned version
        String suuid = new String(UUID.randomUUID().toString());
        newBlock.setABlockID(suuid);
        newBlock.setACreatingProcess("Process:" + Integer.toString(pnum));

        // To be set later, once the block is verified
        newBlock.blockRecord.setAVerificationProcessID("-1");

        // Create SHA256 hash, and signed version; insert those into Block header
        hashAndSignBlockRecord(newBlock);
            
        // Finally, add a timestamp at the new Block's creation
        String T1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
            
        // Add the processID to the end of the timestamp so we don't have collisions (if 2 identical timestamps)
        String TimeStampString = T1 + "." + pnum;
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

            // @TODO don't really use the result...can probably eliminate this list
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
                try{Thread.sleep(20);}catch(Exception e){e.printStackTrace();}
            }

            // SEND KILL SIGNAL INDICATING NO MORE RECORDS
            Block killBlock = new Block();
            killBlock.setABlockID("NO_RECORDS_REMAINING");
            marshalAndMulticast(killBlock);
            try{Thread.sleep(1000);}catch(Exception e){e.printStackTrace();}  

            // Send one more time to break server accept() hang
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

                // Un-marshall String into Block structure
                Block receivedBlock = BlockMarshaller.unmarshalBlock(blockString.toString());

                // Insert the new un-verified block into the priority queue
                UnverifiedBlockProcessor.this.queue.put(receivedBlock);

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
      
            while (true) {
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
// Plucks unverified blocks off priority queue
// Verifies blocks, adds them to new blockchain, and multicasts new blockchain ledger
// **********************************************************************************

class BlockVerifier extends Thread{

    BlockingQueue<Block> queue;
    boolean blocksRemaining;
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public BlockVerifier(BlockingQueue<Block> _queue){
        this.queue = _queue;
        this.blocksRemaining = true;
    }

    // Build random seed String -- Elliott's method
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

        synchronized(Blockchain.LEDGER){

            // For comparison after each loop - check to make sure the Blockchain wasn't updated
            int    curNumBlocks = Blockchain.LEDGER.size();
            String mostRecentHash = Blockchain.LEDGER.prevHash();
            String mostRecentBlockNum = Blockchain.LEDGER.prevBlockNum();

            try {

                // Guaranteed to not fit criteria until we recalculate in loop
                int workNumber = Integer.parseInt("FFFF",16); 
                    
                // Get hash of most recent block on the chain
                String prevBlockHash = Blockchain.LEDGER.prevHash();

                // Add verifying process ID into block - only do once regardless
                block.blockRecord.setAVerificationProcessID(Integer.toString(Blockchain.PID));

                while(workNumber > 20000){

                    // @TODO only have to get previous hash and previous block num once, unless chain is updated
                
                    // Get sequential blockNum of most recent Block on chain, add 1
                    String prevBlockNum = Blockchain.LEDGER.prevBlockNum();
                    String newBlockNum = Integer.toString(Integer.parseInt(prevBlockNum) + 1);
                    block.blockRecord.setBlockNumber(newBlockNum);

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
                        // System.out.println("Block num: " + block.blockRecord.getBlockNumber());
                        addBlockToChain(block);
                        break;
                    }
                    else{
                        // System.out.print("Fails criteria - ");
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

        

    }

    boolean checkBlockUnique(Block block){

        synchronized (Blockchain.LEDGER){
            if (Blockchain.LEDGER.containsID(block.getABlockID())){
                return false;
            }
    
            return true;
        }
        
    }

    // Make sure the Block came from the process we think it did
    boolean verifySignature(Block block){

        try{
            byte[] hashBytes = block.SHA256String.getBytes();
            byte[] signatureBytes = Base64.getDecoder().decode(block.SignedSHA256);
            PublicKey key = Blockchain.publicKeyLookup.get(block.getACreatingProcess());
    
            boolean result = BlockMarshaller.verifySig(hashBytes, key, signatureBytes);
            return result;
        } catch (Exception e){
            e.printStackTrace();
        }
        

        return false;
    }

    public void addBlockToChain(Block block){
        synchronized(Blockchain.LEDGER){
            Blockchain.LEDGER.add(block);
        }
        
    }

    public void multicastBlockchain(){
        PrintStream toServer;
        Socket sock;

        String blockchainString = BlockMarshaller.marshalLedger(Blockchain.LEDGER);
        // System.out.println("Blockchain String: \n " + blockchainString);

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

                boolean signatureVerified = verifySignature(block);

                // If the block is a new one, add to the beginning of the Blockchain and multicast the updated chain
                if (blockIsUnique == true && signatureVerified == true){

                    // Do work to verify block
                    verifyBlock(block);
                    System.out.println("[Verified Block for " + block.blockRecord.getFFname() + "] -- ");
                    // addBlockToChain(block); // <-- this is done in verifyBlock() if the block meets the threshold
                    multicastBlockchain();
                }

            }catch(InterruptedException ie) { ie.printStackTrace(); }

        }

    }

}

// **********************************************************************************
// Reads in multicasted Ledgers
// Compares received Ledgers to current, and replaces current if:
    // Received Ledger is longer
    // Received Ledger has same length but earlier timestamp on head Block
// **********************************************************************************
class LedgerProcessor extends Thread{

    public LedgerProcessor(){

    }

    // **************************
    // Inner class
    // **************************
    class LedgerProcessorWorker extends Thread{

        Socket sock;

        public LedgerProcessorWorker(Socket s){
            this.sock = s;
        }

        public void writeToFile(){

            // Only write to file on Process0
            if (Blockchain.PID != 0) return;
    
            try{
                // Get XML String for Ledger
                String output = BlockMarshaller.marshalLedger(Blockchain.LEDGER);
                    
                FileWriter fileWriter = new FileWriter(Ledger.outputFile);
                PrintWriter printWriter = new PrintWriter(fileWriter);
                printWriter.println(output);
                printWriter.close();
            } catch(IOException e){
                e.printStackTrace();
            }
            
    
        }

        public void updateLedger(Ledger receivedLedger){

            synchronized(Blockchain.LEDGER){

                // Check to see if receivedLedger is longer, or has an earlier head node, than Blockchain.LEDGER
                int curLedgerSize = Blockchain.LEDGER.size();
                int newLedgerSize = receivedLedger.size();

                // Output new/current Ledgers, and what we're doing
                System.out.println("Current Ledger: " + Blockchain.LEDGER.LedgerString());
                System.out.println("New Ledger: " + receivedLedger.LedgerString());

                if (newLedgerSize > curLedgerSize){
                    Blockchain.LEDGER = receivedLedger;
                    System.out.println("Set Ledger to received Ledger");
                }
                else if (newLedgerSize == curLedgerSize){
                    String newLedgerTime = receivedLedger.frontBlock().getTimestamp();
                    String curLedgerTime = Blockchain.LEDGER.frontBlock().getTimestamp();

                    if (newLedgerTime.compareTo(curLedgerTime) < 0){
                        Blockchain.LEDGER = receivedLedger;
                        System.out.println("Set Ledger to received Ledger");
                    }
                    else{
                        System.out.println("Received Ledger Discarded");
                    }
                }
                else{
                    // Do nothing, disregard received Ledger
                    System.out.println("Received Ledger Discarded");
                }

                // Create output file
                writeToFile();

                System.out.println("\n");

            }
        }

        public void run(){

            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                // Read the full Ledger entry as a marshalled string
                StringBuilder ledgerString = new StringBuilder();
                String data;
                while((data = in.readLine()) != null){

                    if (data.equals("NO_RECORDS_REMAINING")){
                        sock.close();
                        return;
                    }

                    ledgerString.append(data);
                    ledgerString.append("\n");
                }

                // Unmarshal Ledger into object
                Ledger receivedLedger = BlockMarshaller.unmarshalLedger(ledgerString.toString());
                // System.out.println("Blockchain String: \n " + BlockMarshaller.marshalLedger(receivedLedger));

                // Decide whether to update Ledger, and replace if criteria met
                updateLedger(receivedLedger);
                

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
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
      
            while (true) {
                sock = servsock.accept(); // Got a new unverified block
                new LedgerProcessorWorker(sock).start(); // So start a thread to process it.
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
public class Blockchain {

    static String serverName = "localhost";
    static int numProcesses = 3; // @TODO Set number based on number given in batch file
    static boolean allProcessesRunning = false;
    static int PID = 0; // Default PID

    // Create public and private keys for this participant
    static final KeyPair keyPair = BlockMarshaller.generateKeyPair(999);

    // Create Public Key lookup using ProcessID
    static final HashMap<String, PublicKey> publicKeyLookup = new HashMap<String, PublicKey>();  // <Process#, Public Key>

    // The Blockchain itself - linked list of blocks
    static Ledger LEDGER = new Ledger();

    public static void getUserInput(){

        // Read from stdin to read input
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        
        try{
           // System.out.print("Enter a command: ");
            
            String input;
            
            
            while(!(input = in.readLine()).equals("quit")){

                String [] tokens = input.split(" ");
                char command = Character.toUpperCase(tokens[0].charAt(0));
                
                switch(command){
                    case 'C':
                        System.out.println(Blockchain.LEDGER.creditString());
                        break;
                    case 'R':
                        break;
                    case 'V':
                        break;
                    case 'L':
                        System.out.println(Blockchain.LEDGER.recordList());
                        break;
                    default:
                        break;
                }
            }

            System.out.println("Done");
            
        }catch(IOException e){
            e.printStackTrace();
        }

    }

    public static void broadcastPublicKey(){

        Socket sock;
        PrintStream toServer;

        try{

            // Combine Process# and Public Key, separated by a space for parsing on receiving end
            String processID = "Process:" + Blockchain.PID;
            String publicKeyString = PublicKeyServer.publicKeyToString(keyPair.getPublic());
            String processKeyPair = processID + " " + publicKeyString;

            for(int i = 0; i < numProcesses; i++){   
                sock = new Socket(serverName, Ports.KeyServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                
                // Get String of public key string data, send it
                toServer.println(processKeyPair);

                toServer.flush();
                sock.close();
            } 

            System.out.println("Sent Public Key for Process" + Integer.toString(Blockchain.PID));

            Thread.sleep(1000);  // Give processes time to set up Keys
        }catch (Exception x) {
            x.printStackTrace ();
        }

    }

    public static void main(String[] args) throws Exception {

        // Assign Process ID
        PID = (args.length < 1) ? 2 : Integer.parseInt(args[0]);

        // Create thread-safe priority queue for processing unverified blocks -- Priority goes by Block timestamp
        final BlockingQueue<Block> queue = new PriorityBlockingQueue<Block>(5, new BlockComparator()); 

        // Perform port number setup for various Processes
        new Ports().setPorts(); 

        /////// Start all servers, which will hang until they start receiving data - reduce chance of bad connections ///

        // Listen for incoming public keys
        new PublicKeyServer().start();

        // Make sure other process's PublicKeyServers are listening
        // By definition Process 2's server is already listening
        try{ Thread.sleep(2000); } catch(Exception e){}

        // New thread to process new unverified blocks and insert into priority queue
        new UnverifiedBlockProcessor(queue).start();

        // Create and start BLockchain server to accept Ledger multicasts
        new LedgerProcessor().start();

        // Broadcast public Key
        if (PID < 2){

            // Gather all other keys, then kick it off with Process 2's key
            broadcastPublicKey();
        }
        else{
            // Process 2 waits for all other processes to start running
            // Then sends its own signal, which starts everyone
            while(publicKeyLookup.size() < 2){
               // wait
               try{ Thread.sleep(10); } catch(Exception e){}
               // System.out.println("Map size: " + Integer.toString(publicKeyLookup.size()));
            }
            // System.out.println("Exited loop");
            try{ Thread.sleep(1000); } catch(Exception e){}
            broadcastPublicKey();
        }

        // Give all processes a chance to receive Process:2 public key
        try{ Thread.sleep(1000); } catch(Exception e){} 
        

        // Wait until we get a key from each process
        // @TODO allProcessesRunning is kind of superfluous since we need Process2 to satisfy the second condition anyway
        while(/*allProcessesRunning == false ||*/ publicKeyLookup.size() < numProcesses){
            // wait
            //System.out.println("Stuck");
        }

         // Extra sleep just to make sure
         try{ Thread.sleep(1000); } catch(Exception e){} 
        
        // New thread to start creating blocks
        new NewBlockCreator().start(); 

        // Sleep for a bit to wait for queue to fill
        try{ Thread.sleep(1000); } catch(Exception e){} 

        // New thread to validate blocks and add to Ledger
        new BlockVerifier(queue).start(); 


        
        // Wait until the blockchain is created before accepting input
        // @TODO come up with condition of blockchain being fully processed
        // try{ Thread.sleep(10000); } catch(Exception e){} 

        // Get user input - for console commands
        getUserInput();

    }

}