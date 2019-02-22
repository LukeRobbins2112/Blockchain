


import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

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
// Reads entries from file, creates new Block entries, and publishes
// **********************************************************************************

class UnverifiedBlockCreator implements Runnable{

    // Threadsafe queue used by UnverifiedBlockCreator and BlockVerifier
    BlockingQueue<String> queue;

    public UnverifiedBlockCreator(BlockingQueue<String> _queue){
        this.queue = queue;
    }

    // **************************
    // Inner class
    // **************************
    class BlockCreator implements Runnable{

        Socket sock;

        UnverifiedBlockWorker (Socket s) {
            sock = s;
        } 

        public void run(){

            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                // Read the full block entry as a marshalled string
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

    public static void main(String[] args){
            
        int q_len = 6; 
        Socket sock;
    
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
      
            while (true) {
                sock = servsock.accept(); // Got a new unverified block
                new BlockCreator(sock).start(); // So start a thread to process it.
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