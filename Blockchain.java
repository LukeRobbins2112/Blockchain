

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.text.*;

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
            BufferedReader br = new BufferedReader(new FileReader(FILENAME));
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