pragma solidity ^0.4.23;

contract fileSale {

    //uint constant depth = 14;
    //uint constant length = 2;
    //uint constant n = 16384;

    enum stage {created, initialized, accepted, keyRevealed, finished}
    stage public phase = stage.created;
    uint public timeout;

    address sender;
    address receiver;
    uint public price; // in wei

    //uint keyCommit ;
    bytes32 public ciphertextRoot;
    bytes32 public ciphertextRoot_r;
    //bytes32 public fileRoot ;

    bytes32 public key;

    uint public complainResult;

    event RequestData(string message, address caller, string input1, string input2, string output);

    event Debug(string message, bytes32 bb);
    event ForSender(string message, bytes32 data);
    event ForReceiver(string message, bytes32 data);

    bytes32 public new_input1;
    bytes32 public new_input2;
    bytes32 public new_output;
    
    constructor() payable public {
        sender = msg.sender;
    }

    // function modifier to only allow calling the function in the right phase only from the correct party
    modifier allowed(address p, stage s) {
        require(phase == s);
        require(block.timestamp < timeout);
        require(msg.sender == p);
        _;
    }

    // go to next phase
    function nextStage() internal {
        phase = stage(uint(phase) + 1);
        timeout = block.timestamp + 10 minutes;
    }

    // constructor is initialize function
    function ininitialize (address _receiver, uint _price, bytes32 _ciphertextRoot) public {

        require(phase == stage.created);
        receiver = _receiver;
        sender = msg.sender;
        price = _price * 1000000000000000000;
        //keyCommit = _keyCommit;
        ciphertextRoot = _ciphertextRoot;
        //fileRoot = _fileRoot;
        complainResult = 3;

        nextStage();
    }

    // function accept
    function accept (bytes32 _ciphertextRoot_receiver) allowed(receiver, stage.initialized) payable public {

        require (msg.value >= price, "Insufficient funds");
        emit ForSender("ciphertextRoot from receiver", _ciphertextRoot_receiver);
        ciphertextRoot_r = _ciphertextRoot_receiver;
        nextStage();
    }

    // function revealKey (key)
    function revealKey (bytes32 _key) allowed(sender, stage.accepted) public {

        //require(keyCommit == keccak256(abi.encodePacked(_key)), "Invalid key");
        emit ForReceiver("key from sender", _key);
        key = _key;
        nextStage();
    }


    // function complain about wrong hash of file
    function noComplain () allowed(receiver, stage.keyRevealed) external payable {

        sender.transfer(price);
        phase = stage.created;
    }


    // refund function is called in case some party did not contribute in time
    function refund () public {

        require (block.timestamp > timeout);
        if (phase == stage.accepted) {
            receiver.transfer(price);
            phase = stage.created;
        }
        else if (phase >= stage.keyRevealed) {
            sender.transfer(price);
            phase = stage.created;
        }
    }


    function verifyRoot(bytes32 datahash, uint index, bytes32 root, bytes32[] memory proof) public pure returns(bool) {
        //bytes32 hash = keccak256(abi.encodePacked(data));  // get hash data for check
        //require (root == ciphertextRoot, "Wrong root");
        require(index < (1 << proof.length), "cannot verify invalid index");
        
        bytes32 hash = datahash;
        for(uint i = 0; i < proof.length; i++) {
            bytes32 element = proof[i];
            if(index % 2 == 0) {
                hash = keccak256(abi.encodePacked(hash, element));
            } else {
                hash = keccak256(abi.encodePacked(element, hash));
            }
            //index = index / 2;
            index = index >> 1;
        }
        return hash == root;
    }

    function verifyChild(bytes32[] input, bytes32 output) public pure returns (bool){
        //emit Debug("verifyChild computedHash:", keccak256(abi.encodePacked(input[0], input[1])));
        return keccak256(abi.encodePacked(input[0], input[1])) == output;
    }

    function complain (uint indexIn, uint indexOut, bytes32 root, bytes32[] proofZin, bytes32[] proofZout, bytes32[] input, bytes32 output, bytes32[] inputZH, bytes32 outputZH) allowed(receiver, stage.keyRevealed) public {

        complainResult = 0;
        require (root == ciphertextRoot, "Wrong root");
        //require (root == fileRoot, "Wrong root, complain fail ...");
        //require (verifyChild(input, output), "Child correct, complain fail ...");

        // 1.解密data
            // 外包
            // output 和 input 已經解密完成，並且hash過了
            // outputZ 為沒有解密過的錯誤data，並且hash過了

        // 2.進行驗證

        bool isChildVerified = verifyChild(input, output);

        require(!isChildVerified, "Child verification succeeded when it should have failed");

        require(verifyRoot(outputZH, indexOut, root, proofZout), "Root verification failed (output)");
        require(verifyRoot(inputZH[0], indexIn, root, proofZin), "Root verification failed (input)");
        require(inputZH[1] == proofZin[0], "inputZH[1] should equal to proofZin[0]");

        if (!isChildVerified) {
            // 3.退款
            complainResult = 1;
            receiver.transfer(price);
            phase = stage.created;
        } 
        else {
            complainResult = 0;
        }
    }

    function getComplainResult() public view returns (string) {
        if (complainResult==1){
            return "Buyer complain Success";
        }
        else if(complainResult==0){
            return "Buyer complain Fail";
        }
        else{
            return "None";
        }
    }

    function getCiphertextRoot_r() public view returns (bytes32) {
        return ciphertextRoot_r;
    }

    function getKey() public view returns (bytes32) {
        return key;
    }

    //   -------------------------- test --------------------------

    function verifyChild_request_ver(bytes32 input1, bytes32 input2, bytes32 output) public pure returns (bool){

        bytes32 computedHash = keccak256(abi.encodePacked(input1, input2));
        return computedHash == output;
    }

    function complain_request_ver(uint index, bytes32 root, bytes32[] proof, string input1, string input2, string output) allowed(receiver, stage.keyRevealed) public {

        // 1.解密data
        // output 和 input 尚未解密
        // 外包
        requestData(input1, input2, output);
        // 回傳 new_input1, new_input2, new_output 為解密過，並且進行過hash

        // 2.進行驗證
        bool isRootVerified = verifyRoot(new_output, index, root, proof);
        bool isChildVerified = verifyChild_request_ver(new_input1, new_input2, new_output);

        require(isRootVerified, "=====Root verification failed=====");
        require(!isChildVerified, "=====Child verification succeeded when it should have failed=====");

        if (isRootVerified && !isChildVerified) {
            // 3.退款
            complainResult = 1;
            receiver.transfer(price);
            phase = stage.created;
        } 
        else {
            complainResult = 0;
        }
    }

    function requestData(string input1, string input2, string output) public {
        emit RequestData("Request to decrypt input and output", msg.sender, input1, input2, output);
    }

    function receiveData(bytes32 data1, bytes32 data2, bytes32 data3) public {
        // 处理外部程序返回的数据
        new_input1 = data1;
        new_input2 = data2;
        new_output = data3;
    }

    function getTimeout() public view returns (uint) {
        return timeout;
    }
    function getNow() public view returns (uint) {
        return block.timestamp;
    }
    function getNewOutput() public view returns (bytes32) {
        return new_output;
    }

    function refund_for_test () public {
        sender.transfer(price);
        phase = stage.created;
    }

}
