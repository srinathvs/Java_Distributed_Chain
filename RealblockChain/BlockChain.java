/*
Security threats to this program :
the work done is not that computationally expensive, if any real credit is given to the process, it would be easy to
steal credit, as the chance of guessi the right answer is 1 in 3. the ports can be listened in by other processes
that can be malicious in nature to the system, and can ( if at a lower latency, snoop on the messages and possibly get
credited for other processes' work. my current iteration of this program is not really encrypted in any way either,
and all the data is in a readable format.

 */

/*


BlockChain.java

V1.6 2020-4-11
author : Srinath
Java version : 1.8.0_261-b12

 */



/* BlockChain.java


The web sources:

https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html

One version of the JSON jar file here:
https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/

You will need to download gson-2.8.2.jar into your classpath / compiling directory.

To compile and run:

javac -cp "gson-2.8.2.jar" BlockJ.java
java -cp ".;gson-2.8.2.jar" BlockJ

-----------------------------------------------------------------------------------------------------*/

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.security.spec.*;
import java.security.*;
import java.security.MessageDigest;


import java.util.*;
import java.text.*;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;



//Class used to define the block records
class BlockRecord implements Serializable{
    /* Examples of block fields. You should pick, and justify, your own set: */
    String BlockID;
    String VerificationProcessID;
    String PreviousHash; // We'll copy from previous block
    UUID uuid; // Just to show how JSON marshals this binary data.
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;
    String RandomSeed;
    String WinningHash;
    String TimeStamp;


    /* Examples of accessors for the BlockRecord fields: */
    public String getBlockID() {return BlockID;}
    public void setBlockID(String BID){this.BlockID = BID;}

    public String getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public String getPreviousHash() {return this.PreviousHash;}
    public void setPreviousHash (String PH){this.PreviousHash = PH;}

    public UUID getUUID() {return uuid;} // Later will show how JSON marshals as a string. Compare to BlockID.
    public void setUUID (UUID ud){this.uuid = ud;}

    public String getLname() {return Lname;}
    public void setLname (String LN){this.Lname = LN;}

    public String getFname() {return Fname;}
    public void setFname (String FN){this.Fname = FN;}

    public String getSSNum() {return SSNum;}
    public void setSSNum (String SS){this.SSNum = SS;}

    public String getDOB() {return DOB;}
    public void setDOB (String RS){this.DOB = RS;}

    public String getDiag() {return Diag;}
    public void setDiag (String D){this.Diag = D;}

    public String getTreat() {return Treat;}
    public void setTreat (String Tr){this.Treat = Tr;}

    public String getRx() {return Rx;}
    public void setRx (String Rx){this.Rx = Rx;}

    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed (String RS){this.RandomSeed = RS;}

    public String getWinningHash() {return WinningHash;}
    public void setWinningHash (String WH){this.WinningHash = WH;}

    public String getTimeStamp(){return TimeStamp;}
    public void setTimeStamp(String Time){this.TimeStamp =Time;}


}
//common class used for port functionality
class Ports{
    public static int KeyServerPortBase = 4610;
    public static int UnverifiedBlockServerPortBase = 4710;
    public static int BlockchainServerPortBase = 4810;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + BlockChain.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + BlockChain.PID;
        BlockchainServerPort = BlockchainServerPortBase + BlockChain.PID;
    }
}

// this keep public keys in sync between various processes
class PublicKeyWorker extends Thread { // Worker thread to process incoming public keys
    Socket keySock; // Class member, socket, local to Worker.
    PublicKeyWorker (Socket s) {keySock = s;} // Constructor, assign arg s to local sock
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
            String data = in.readLine ();
            System.out.println("Got key: " + data);
            keySock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

//Used to make public key worker threads which keep public keys in sync
class PublicKeyServer implements Runnable {
    //public ProcessBlock[] PBlock = new ProcessBlock[3]; // Typical would be: One block to store info for each process.

    public void run(){
        int q_len = 6;
        Socket keySock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                keySock = servsock.accept();
                new PublicKeyWorker (keySock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

//Keeps a reference to the priority queue and is bound to it, to immediately reflect changes made to the queue
class UnverifiedBlockServer implements Runnable {
    BlockingQueue<BlockRecord> queue;
    UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
        this.queue = queue; // Constructor binds our prioirty queue to the local variable.
    }

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2)
        {
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1.equals(s2)) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };


    /* Inner class to share priority queue. We are going to place the unverified blocks (UVBs) into this queue in the order
       we get them, but they will be retrieved by a consumer process sorted by TimeStamp of when created. */

    class UnverifiedBlockWorker extends Thread { // Receive a UVB and put it into the shared priority queue.
        Socket sock; // Class member, socket, local to Worker.
        UnverifiedBlockWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
        BlockRecord BR = new BlockRecord();

        public void run(){
            // System.out.println("In Unverified Block Worker");
            try{
                ObjectInputStream unverifiedIn = new ObjectInputStream(sock.getInputStream());
                BR = (BlockRecord) unverifiedIn.readObject(); // Read in the UVB as an object
                System.out.println("Received UVB: " + BR.getTimeStamp() + " " + BR.getTimeStamp() + " " + BR.getFname() + " " + BR.getLname());
                queue.put(BR); // Note: make sure you have a large enough blocking priority queue to accept all the puts
                sock.close();
            } catch (Exception x){x.printStackTrace();}
        }
    }

    public void run(){ // Start up the Unverified Block Receiving Server
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = UVBServer.accept(); // Got a new unverified block
                // System.out.println("Got connection to UVB Server.");
                new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


//Unverified blocks are received and must be unpacked and moved from the priority queue to be signed and verified

class UnverifiedBlockConsumer implements Runnable {
    PriorityBlockingQueue<BlockRecord> queue; // Passed from BC object.
    int PID;
    String ALPHA_NUMERIC_STRING = "ABSCDSAGADS23451";
    String CSC435BlockChain;
    UnverifiedBlockConsumer(PriorityBlockingQueue<BlockRecord> queue, String JSONString){
        this.queue = queue; // Constructor binds our prioirty queue to the local variable.
        this.CSC435BlockChain = JSONString;
        PID = BlockChain.PID;
    }

    public static String ByteArrayToString(byte[] ba){
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for(int i=0; i < ba.length; i++){
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }

    public static String randomAlphaNumeric(int count) {
        String ALPHA_NUMERIC_STRING = "ABSCDSAGADS23451";
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    public void run(){

        BlockRecord tempRec;
        String BlockID;
        String VerificationProcessID;
        String PreviousHash;
        UUID uuid;
        String Fname;
        String Lname;
        String SSNum;
        String DOB;
        String Diag;
        String Treat;
        String Rx;
        String RandomSeed;
        String WinningHash;
        String TimeStamp;
        PrintStream toBlockChainServer;
        Socket BlockChainSock;
        String newblockchain;
        String fakeVerifiedBlock;
        Random r = new Random();

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
        try{
            while(true){
                //consumer process takes from the priority queue and then does some work on the data
                tempRec = queue.take();
                Fname = tempRec.getFname();
                Lname =tempRec.getLname();
                SSNum = tempRec.getSSNum();
                DOB = tempRec.getDOB();
                Diag = tempRec.getDiag();
                Treat = tempRec.getTreat();
                Rx = tempRec.getRx();
                RandomSeed = tempRec.getRandomSeed();
                BlockID = tempRec.getBlockID();
                TimeStamp =tempRec.getTimeStamp();



	//Actually doing work here. the completed work is then added to the block as the winning hash.
                int workNumber = 0;     // Number will be between 0000 (0) and FFFF (65535), here's proof:
                workNumber = Integer.parseInt("0000",16); // Lowest hex value
                System.out.println("0x0000 = " + workNumber);

                workNumber = Integer.parseInt("FFFF",16); // Highest hex value
                System.out.println("0xFFFF = " + workNumber + "\n");
                String stringOut = "";
                String stringIn = tempRec.Fname;
                String concatString = "";
                //the actual data to be appended to the random string and hashed on finding the solution
                String data = Fname + Lname + SSNum + DOB + Diag + Treat + Rx;
                String randString = "";
                try {

                    for(int i=1; i<20; i++){ // Limit how long we try for this example.
                        randString = randomAlphaNumeric(8); // Get a new random AlphaNumeric seed string
                        concatString = data + randString; // Concatenate with our input string (which represents Blockdata)
                        MessageDigest MD = MessageDigest.getInstance("SHA-256");
                        byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value

                        //stringOut = DatatypeConverter.printHexBinary(bytesHash); // Turn into a string of hex values Java 1.8
                        stringOut = ByteArrayToString(bytesHash); // Turn into a string of hex values, java 1.9
                        System.out.println("Hash is: " + stringOut);

                        workNumber = Integer.parseInt(stringOut.substring(0,4),16); // Between 0000 (0) and FFFF (65535)
                        System.out.println("First 16 bits in Hex and Decimal: " + stringOut.substring(0,4) +" and " + workNumber);
                        if (!(workNumber < 20000)){  // lower number = more work.
                            System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
                        }
                        if (workNumber < 20000){
                            System.out.format("%d IS less than 20,000 so puzzle solved!\n", workNumber);
                            System.out.println("The seed (puzzle answer) was: " + randString);


                            break;
                        }


                    }
                }catch(Exception ex) {ex.printStackTrace();}

                //Hashing teh data with solution and process ID together
                String StringtoHash = randString + data;
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update (StringtoHash.getBytes());
                byte byteData[] = md.digest();

                // CDE: Convert the byte[] to hex format. THIS IS NOT VERFIED CODE:
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < byteData.length; i++) {
                    sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                }
                //Verifyign signature here
                String SHA256String = sb.toString();
                byte[] digitalSignature = BlockChain.signData(SHA256String.getBytes(), BlockChain.myKeyPair.getPrivate());

                boolean verified = BlockChain.verifySig(SHA256String.getBytes(), BlockChain.myKeyPair.getPublic(), digitalSignature);
                System.out.println("Has the signature been verified: " + verified + "\n");

                System.out.println("Hexidecimal byte[] Representation of Original SHA256 Hash: " + SHA256String + "\n");

                WinningHash = StringtoHash;
                tempRec.setWinningHash(WinningHash);


                //cehcking final strin before wirting to JSON ( I had errors here )

                concatString = // "Get a string of the block so we can hash it.
                        tempRec.getBlockID() +
                                tempRec.getVerificationProcessID() +
                                tempRec.getPreviousHash() +
                                tempRec.getFname() +
                                tempRec.getLname() +
                                tempRec.getSSNum() +
                                tempRec.getRx() +
                                tempRec.getDOB() +
                                tempRec.getRandomSeed()+
                                tempRec.getWinningHash();
                System.out.println(concatString);
                WriteJSON(tempRec);

                //Filler code, can be removed, does nothing
                if(!BlockChain.CSC435BlockChain.contains(Fname.substring(1, Fname.length()))){ // Crude, but excludes most duplicates.
                    fakeVerifiedBlock = "[" + Fname + " verified by P" + BlockChain.PID + " at time ]";
                    String tempblockchain = fakeVerifiedBlock + BlockChain.CSC435BlockChain; // add the verified block to the chain
                    System.out.println(fakeVerifiedBlock);

                    //Required for actually sending to all processes ( multicast func )
                    for(int i=0; i < BlockChain.numProcesses; i++){
                        BlockChainSock = new Socket(BlockChain.serverName, Ports.BlockchainServerPortBase + i );
                        toBlockChainServer = new PrintStream(BlockChainSock.getOutputStream());
                        toBlockChainServer.println(CSC435BlockChain); toBlockChainServer.flush();
                        BlockChainSock.close();

                    }
                }
                Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block

            }
        }catch (Exception e) {System.out.println(e);}
    }
    public void WriteJSON(BlockRecord blockRecord) {
        System.out.println("=========> In WriteJSON <=========\n");

        //Gathering all the input field arguments and concatenating with the previous block
        String catRecord = // "Get a string of the block so we can hash it.
                blockRecord.getBlockID() +
                        blockRecord.getVerificationProcessID() +
                        blockRecord.getPreviousHash() +
                        blockRecord.getFname() +
                        blockRecord.getLname() +
                        blockRecord.getSSNum() +
                        blockRecord.getRx() +
                        blockRecord.getDOB() +
                        blockRecord.getRandomSeed()+
                        blockRecord.getWinningHash();

        System.out.println("String blockRecord is: " + catRecord);

        /* Now make the SHA-256 Hash Digest of the block: */
        CSC435BlockChain += catRecord;
        String SHA256String = "";

        /* Now let's see what the JSON of the full block looks like: */

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the Java object to a JSON String:
        String json = gson.toJson(CSC435BlockChain);

        System.out.println("\nJSON String blockRecord is: " + json);

        // Write the JSON object to a file:
        try (FileWriter writer = new FileWriter("blockRecord.json")) {
            gson.toJson(CSC435BlockChain, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}


//Creates new bloackchains post verification of blocks
class BlockchainWorker extends Thread { // Class definition
    Socket sock; // Class member, socket, local to Worker.
    BlockchainWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String blockData = "";
            String blockDataIn;
            while((blockDataIn = in.readLine()) != null){
                blockData = blockData + "\n" + blockDataIn;
            }
            BlockChain.CSC435BlockChain = blockData; // Would normally have to check first for winner blockchain before replacing.
            System.out.println("         --NEW BLOCKCHAIN--\n" + BlockChain.CSC435BlockChain + "\n\n");
            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}


class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}



public class BlockChain {
    //Default Process ID
    public static int PID = 0;
    public static String FILENAME;

    //Keypair for current Process
    static KeyPair myKeyPair;

    //Storing all public keys here
    static PublicKey[] allPublicKeys = new PublicKey[3];

    //List of records
    LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();

    static String CSC435BlockChain = "";

    // This queue of UVBs must be concurrent because it is shared by producer threads and the consumer thread
    final PriorityBlockingQueue<BlockRecord> ourPriorityQueue = new PriorityBlockingQueue<>(150, BlockTSComparator);

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2)
        {
            //System.out.println("In comparator");
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };
    //the final BlockChain


    static String serverName = "localhost";

    //TODO : Change process number dynamically based on maximum of processes needed
    //Need to change this variable for more processes
    static int numProcesses = 3;

    public static void main(String[] args) throws InterruptedException {

        BlockChain bc = new BlockChain();
        if (args.length < 1) PID = 0;
        else if (args[0].equals("0")){ PID = 0; FILENAME = "BlockInput0.txt";}
        else if (args[0].equals("1")){ PID = 1; FILENAME = "BlockInput1.txt";}
        else if (args[0].equals("2")){ PID = 2; FILENAME = "BlockInput2.txt";}
        else {PID = 0; FILENAME = "BlockInput0.txt";}

        bc.run();


    }

public void run() throws InterruptedException {
    System.out.println("\nProcess" + PID + " is starting up : \n");

    try {

        //Creating key from random seed
        Random RNG = new Random();
        int randomSeed = RNG.nextInt(1500);
        myKeyPair = generateKeyPair(randomSeed);

        //Inserign public keys into all piblic keys
        allPublicKeys[PID] = myKeyPair.getPublic();

    } catch (Exception e) {}

    //setup the ports of the system to send and receive the blocks
    new Ports().setPorts();
    //Setup dummy block

    System.out.println("size of the list of records is : "+recordList);
    Thread.sleep(3000);
    new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
    new Thread(new UnverifiedBlockServer(ourPriorityQueue)).start(); // New thread to process incoming unverified blocks
    new Thread(new BlockchainServer()).start(); // New thread to process incomming new blockchains
    try{Thread.sleep(3000);}catch(Exception e){} // Wait for servers to start.
    KeySend();
    try{Thread.sleep(3000);}catch(Exception e){}
    //Multicast new unverified blocks to all processes
    new BlockChain().UnverifiedSend();
    //Wait for the priority queue to be filled up
    try{Thread.sleep(3000);}catch(Exception e){}
    new Thread(new UnverifiedBlockConsumer(ourPriorityQueue, CSC435BlockChain)).start(); // Start consuming the queued-up unverified blocks

    Thread.sleep(1000);

}

//Creates a dummy block with some sample input params
    public void createDummyBlock() {
        BlockRecord dummyData = new BlockRecord();
        String line = "Random assignment 1995.09.17 115-334-123 Insomnia Pills Exercise";
        try {

            //these are input params for dummy block
            String[] params = line.split("\\s");
            dummyData.setVerificationProcessID(String.valueOf(BlockChain.PID));
            dummyData.setUUID(UUID.randomUUID());
            Date date = new Date();
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + BlockChain.PID;
            dummyData.setTimeStamp(TimeStampString);
            dummyData.setFname(params[0]);
            dummyData.setLname(params[1]);
            dummyData.setDOB(params[2]);
            dummyData.setSSNum(params[3]);
            dummyData.setDiag(params[4]);
            dummyData.setTreat(params[5]);
            dummyData.setRx(params[6]);


            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            Random rr = new Random(); //
            int rval = rr.nextInt(16777215); // This is 0xFFFFFF -- YOU choose what the range is

            // In real life you'll want these much longer. Using 6 chars to make debugging easier.
            String randSeed = String.format("%06X", rval & 0x0FFFFFF);  // Mask off all but trailing 6 chars.
            rval = rr.nextInt(16777215);
            String randSeed2 = Integer.toHexString(rval);
            dummyData.setRandomSeed(randSeed2);

            recordList.add(dummyData);


        } catch (Exception e) {
            System.out.println("Error creating the dummy block");

        }
        String SHA256String = "";
        try{
            MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
            ourMD.update (line.getBytes());
            byte byteData[] = ourMD.digest();

            // CDE: Convert the byte[] to hex format. THIS IS NOT VERFIED CODE:
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            SHA256String = sb.toString(); // For ease of looking at it, we'll save it as a string.
        }catch(NoSuchAlgorithmException x){};

        dummyData.setWinningHash(SHA256String); // Here we just assume the first hash is a winner. No real *work*.
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the Java object to a JSON String:
        String json = gson.toJson(dummyData);

        System.out.println("\nJSON String blockRecord is: " + json);

        // Write the JSON object to a file:
        try (FileWriter writer = new FileWriter("blockRecord.json")) {
            gson.toJson(dummyData, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    //Used to generate keypairs both public and private
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    //Used to sign the data
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    //this code is used to send public keys to all other processes
    public static void KeySend(){
        Socket sock;
        PrintStream toServer;
        try{
            //Iterates over total processes until it sends its keys to all the processes
            for(int i=0; i< numProcesses; i++){
                sock = new Socket(serverName, Ports.KeyServerPortBase + i );
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println("KeyProcess" + BlockChain.PID); toServer.flush();
                toServer.println(Base64.getEncoder().encodeToString(myKeyPair.getPublic().getEncoded())); toServer.flush();
                sock.close();
            }
        }catch (Exception x) {x.printStackTrace ();}
    }

   //Multuicasts an unverified block to all processes as an object. ( does not use marshalling here )
    public void UnverifiedSend () throws InterruptedException { // Multicast some unverified blocks to the other processes
        //client Connection being made to the block accepting server, which adds these blocsk to the priority queue which is ordered by timestamps
        Socket UVBsock;
        BlockRecord tempRec;

        createDummyBlock();
        //Get blocks from input files
        recordList = getBlocksFromFile();
        String T1;
        String TimeStampString;
        Date date;
        Random r = new Random();

        Thread.sleep(1000); // wait for public keys to settle, normally would wait for an ack that it was received.
        try{
            System.out.println("Recoreded list is of the size : " +recordList);
            Collections.shuffle(recordList); // Shuffle the list to later demonstrate how the priority queue sorts them.

            Iterator<BlockRecord> iterator;

            ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
            for(int i = 0; i < numProcesses; i++){// Send some sample Unverified Blocks (UVBs) to each process
                System.out.println("Sending UVBs to process " + i + "...");
                iterator = recordList.iterator(); // We saved our samples in a list, restart at the beginning each time.
                while(iterator.hasNext()){
                    // Client connection. Triggers Unverified Block Worker in other process's UVB server:
                    UVBsock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i );
                    toServerOOS = new ObjectOutputStream(UVBsock.getOutputStream());
                    Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
                    tempRec = iterator.next();
                    // System.out.println("UVB TempRec for P" + i + ": " + tempRec.getTimeStamp() + " " + tempRec.getData());
                    toServerOOS.writeObject(tempRec); // Send the unverified block record object
                    toServerOOS.flush();
                    UVBsock.close();
                }
            }
            Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
        }catch (Exception x) {x.printStackTrace ();}
    }

    //gets Blocks from file
    public LinkedList<BlockRecord> getBlocksFromFile() {

        BlockRecord tempRec;
        int n = 0;
        try {
            String line;
            BufferedReader br = new BufferedReader(new FileReader(BlockChain.FILENAME));
            while ((line = br.readLine()) != null) {
                String[] params = line.split("\\s");
                BlockRecord blockRecord = new BlockRecord();
                blockRecord.getVerificationProcessID();
                blockRecord.setUUID(UUID.randomUUID());
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + BlockChain.PID;
                blockRecord.setTimeStamp(TimeStampString);
                blockRecord.setFname(params[0]);
                blockRecord.setLname(params[1]);
                blockRecord.setDOB(params[2]);
                blockRecord.setSSNum(params[3]);
                blockRecord.setDiag(params[4]);
                blockRecord.setTreat(params[5]);
                blockRecord.setRx(params[6]);

                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                Random rr = new Random(); //
                int rval = rr.nextInt(16777215); // This is 0xFFFFFF -- YOU choose what the range is

                // In real life you'll want these much longer. Using 6 chars to make debugging easier.
                String randSeed = String.format("%06X", rval & 0x0FFFFFF);  // Mask off all but trailing 6 chars.
                rval = rr.nextInt(16777215);
                String randSeed2 = Integer.toHexString(rval);
                blockRecord.setRandomSeed(randSeed2);
                n++;
                recordList.add(blockRecord);
            }

            br.close();
        } catch (Exception e) {
        }

        //reading records in the queue and priority queue
        System.out.println(n + " records read." + "\n");
        System.out.println("Records in the linked list:");

        // Show names from records read into the linked list:
        Iterator<BlockRecord> iterator = recordList.iterator();
        while(iterator.hasNext()){
            tempRec = iterator.next();
            System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
        }
        System.out.println("");

        iterator=recordList.iterator();

        System.out.println("The shuffled list:"); // Shuffle the list to later demonstrate the priority queue.
        Collections.shuffle(recordList);
        while(iterator.hasNext()){
            tempRec = iterator.next();
            System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
        }
        System.out.println("");

        iterator=recordList.iterator();

        System.out.println("Placing shuffled records in our priority queue...\n");
        while(iterator.hasNext()){
            ourPriorityQueue.add(iterator.next());
        }

        System.out.println("Priority Queue (restored) Order:");

        while(true){
            tempRec = ourPriorityQueue.poll(); // For consumer thread you'll want .take() which blocks while waiting.
            if (tempRec == null) break;
            System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
        }
        System.out.println("\n\n");

        return recordList;

    }
    //Used for reading the written JSON

    public void ReadJSON(){
        System.out.println("\n=========> In ReadJSON <=========\n");

        Gson gson = new Gson();

        try (Reader reader = new FileReader("blockChainLedgerRecord.json")) {

            // Read and convert JSON File to a Java Object:
            BlockRecord blockRecordIn = gson.fromJson(reader, BlockRecord.class);

            // Print the blockRecord:
            System.out.println(blockRecordIn);
            System.out.println("Name is: " + blockRecordIn.Fname + " " + blockRecordIn.Lname);

            String INuid = blockRecordIn.uuid.toString();
            System.out.println("String UUID: " + blockRecordIn.BlockID + " Stored-binaryUUID: " + INuid);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Used for writing JSON to the file
    public void WriteJSON(BlockRecord blockRecord) {
        System.out.println("=========> In WriteJSON <=========\n");

        String catRecord = // "Get a string of the block so we can hash it.
                blockRecord.getBlockID() +
                        blockRecord.getVerificationProcessID() +
                        blockRecord.getPreviousHash() +
                        blockRecord.getFname() +
                        blockRecord.getLname() +
                        blockRecord.getSSNum() +
                        blockRecord.getRx() +
                        blockRecord.getDOB() +
                        blockRecord.getRandomSeed()+
                        blockRecord.getWinningHash();

        System.out.println("String blockRecord is: " + catRecord);

        /* Now make the SHA-256 Hash Digest of the block: */
        CSC435BlockChain += catRecord;
        String SHA256String = "";

        /* Now let's see what the JSON of the full block looks like: */

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the Java object to a JSON String:
        String json = gson.toJson(blockRecord);

        System.out.println("\nJSON String blockRecord is: " + json);

        // Write the JSON object to a file:
        try (FileWriter writer = new FileWriter("blockRecord.json")) {
            gson.toJson(blockRecord, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


    }






