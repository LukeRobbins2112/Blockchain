
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

/* General facilities */
import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.text.*;


class BlockEncryption{

    public BlockEncryption(){

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

  public static KeyPair generateKeyPair(long seed) throws Exception {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
  }

  public static String createHash(){

    return "";
  }

}

// **********************************************************************************
// BlockRecord "struct", containing all the XML fields and methods
// **********************************************************************************

@XmlRootElement
class BlockRecord {
  /* Examples of block fields: */
  String SHA256String;
  String SignedSHA256;
  String BlockID;
  String VerificationProcessID;
  String CreatingProcess;
  String PreviousHash;
  String Fname;
  String Lname;
  String SSNum;
  String DOB;
  String Diag;
  String Treat;
  String Rx;

  public String getASHA256String() {return SHA256String;}
  @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}

  public String getASignedSHA256() {return SignedSHA256;}
  @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

  public String getACreatingProcess() {return CreatingProcess;}
  @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

  public String getAVerificationProcessID() {return VerificationProcessID;}
  @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

  public String getABlockID() {return BlockID;}
  @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}

  public String getFSSNum() {return SSNum;}
  @XmlElement
    public void setFSSNum(String SS){this.SSNum = SS;}

  public String getFFname() {return Fname;}
  @XmlElement
    public void setFFname(String FN){this.Fname = FN;}

  public String getFLname() {return Lname;}
  @XmlElement
    public void setFLname(String LN){this.Lname = LN;}

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

}

// **********************************************************************************
// Used for port lookups
// **********************************************************************************
class Ports{
    public static int KeyServerPortBase = 6050;
    public static int UnverifiedBlockServerPortBase = 6051;
    public static int BlockchainServerPortBase = 6052;
  
    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;
  
    public void setPorts(){
      KeyServerPort = KeyServerPortBase + (Blockchain.PID * 1000);
      UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID * 1000);
      BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID * 1000);
    }
  }

// **********************************************************************************
// Produces new unverified blocks from file and multicasts them out
// **********************************************************************************

class NewBlockCreator{

    private static String fileName;

    public NewBlockCreator(){
        fileName = "BlockInput" + Integer.toString(Blockchain.PID) + ".txt";
    }

    public void createBlocks(){

        try{
            BufferedReader br = new BufferedReader(new FileReader(fileName));
            String input;

            // @TODO for now using a fixed number of block records
            BlockRecord[] blockArray = new BlockRecord[20];

            for (int i = 0; i < 20 && (input = br.readLine()) != null; i++){

                // Create a new, empty BlockRecord
                blockArray[i] = new BlockRecord();

                // Insert the un-signed hash (@TODO call a hash on the raw data for this)
                blockArray[i].setASHA256String("SHA string goes here...");

                // Insert the signed hash, using the private key and entry data 
                // (@TODO get the hash above, and sign it using the java.security.Signature class as shown in BlockH.java)
                blockArray[i].setASignedSHA256("Signed SHA string goes here...");

                /* CDE: Generate a unique blockID. This would also be signed by creating process: */
                idA = UUID.randomUUID();
                suuid = new String(UUID.randomUUID().toString());
                blockArray[n].setABlockID(suuid);
                blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));

                // @TODO sign the blockID and include here
                blockArray[n].setAVerificationProcessID("To be set later...");
                
                /* CDE put the file data into the block record: */
                // Tokenize the input, just pack each field into the appropriate header
                tokens = InputLineStr.split(" +"); 
                blockArray[n].setFSSNum(tokens[iSSNUM]);
                blockArray[n].setFFname(tokens[iFNAME]);
                blockArray[n].setFLname(tokens[iLNAME]);
                blockArray[n].setFDOB(tokens[iDOB]);
                blockArray[n].setGDiag(tokens[iDIAG]);
                blockArray[n].setGTreat(tokens[iTREAT]);
                blockArray[n].setGRx(tokens[iRX]);

            }

        } catch(IOException e){
            e.printStackTrace();
        }
        

    }

}

// **********************************************************************************
// Receives unverified blocks and places them on priority queue to be processed
// **********************************************************************************

class UnverifiedBlockProcessor implements Runnable{

    // Threadsafe queue used by UnverifiedBlockProcessor and BlockVerifier
    BlockingQueue<String> queue;

    public UnverifiedBlockProcessor(BlockingQueue<String> _queue){
        this.queue = queue;
    }

    // **************************
    // Inner class
    // **************************
    class BlockProcessor implements Runnable{

        Socket sock;

        BlockProcessor (Socket s) {
            sock = s;
        } 

        public void run(){

            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                // Read the full block entry as a marshalled string
                // @TODO might just be sent as a single string, might not have to "build" it like this
                StringBuilder blockString = new StringBuilder();
                String data;
                while((data = in.readLine()) != null){
                    blockString.append(data);
                }

                // Insert the new un-verified block into the priority queue
                // @TODO this just puts the string in there, but should we have a key/value where the timestamp is the key used for order?
                queue.put(blockString.toString());

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

public class Blockchain{

    static String serverName = "localhost";
    static String blockchain = "[First block]";
    static int numProcesses = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N
    static int PID = 0; // Default PID

    public static void main(String[] args){

        // Assign Process ID
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);

        // Create thread-safe priority queue for processing unverified blocks
        final BlockingQueue<String> queue = new PriorityBlockingQueue<>(); 

        // Perform port number setup for various Processes
        new Ports().setPorts(); 
    }

}