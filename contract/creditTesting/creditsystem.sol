pragma solidity ^ 0.4.24;

contract CreditSystemTesting {
    mapping (address => string) public DataSet;
    address[] public HashList;

    function HashListLength() public constant returns(uint) {
        return HashList.length;
    }

    function addData(string data) public {
        HashList.push(msg.sender);
        DataSet[msg.sender] = data;
    }
}