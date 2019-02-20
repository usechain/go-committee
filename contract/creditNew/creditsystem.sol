pragma solidity >=0.4.0 <0.6.0;

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev give an account access to this role
     */
    function add(Role storage role, address account) internal {
        require(account != address(0));
        require(!has(role, account));

        role.bearer[account] = true;
    }

    /**
     * @dev remove an account's access to this role
     */
    function remove(Role storage role, address account) internal {
        require(account != address(0));
        require(has(role, account));

        role.bearer[account] = false;
    }

    /**
     * @dev check if an account has this role
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0));
        return role.bearer[account];
    }
}

contract SignerRole {
    using Roles for Roles.Role;

                    event SignerAdded(address indexed account);
    event SignerRemoved(address indexed account);

    Roles.Role private _signers;

    constructor () internal {
        _addSigner(msg.sender);
    }

    modifier onlySigner() {
        require(isSigner(msg.sender));
        _;
    }

    function isSigner(address account) public view returns (bool) {
        return _signers.has(account);
    }

    function addSigner(address account) public onlySigner {
        _addSigner(account);
    }

    function renounceSigner() public {
        _removeSigner(msg.sender);
    }

    function _addSigner(address account) internal {
        _signers.add(account);
        emit SignerAdded(account);
    }

    function _removeSigner(address account) internal {
        _signers.remove(account);
        emit SignerRemoved(account);
    }
}

contract CreditSystem is SignerRole{

    event NewUserRegister(address indexed addr, bytes32 indexed hash);
    event NewIdentity(address indexed addr, bytes32 indexed hash);

    mapping (address => UseID) IDs;
    mapping (bytes32 => UseData) DataSet;
    bytes32[] public unregister;

    struct Hash {
        bytes32 hash;
        bool verify;
    }

    struct UseID {
        //address addr;             // msg.sender
        address useId;              // msg.sender
        string publicKey;           // user's publicKey
        Hash baseHash;              // keccak(idtype + idnum) and verified flag
        HashList hl;                // other certificate's hash and verifiy flag list implements by struct
    }

    struct UseData {
        bytes identity;             // certificate's data
        bytes issuer;               // certificate's issuer
        bool verify;                // same flag with HashList verifies
        uint index;
    }

    struct HashList {
        bytes32[] hashes;           // keccak(idtype + idnum)
        bool[] verifies;            // certificate's status
    }


    function register(string _publicKey,
        //address _useId,
        bytes32 _hashKey,
        bytes _identity,
        bytes _issuer)
    public
    payable
    returns(bool){
        address addr = msg.sender;
        require(IDs[addr].useId == 0); // unregistered user
        uint index = unregister.push(_hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index);
        DataSet[_hashKey] = ud;
        UseID memory user = UseID(addr, _publicKey, Hash(_hashKey, false), HashList(new bytes32[](0), new bool[](0)));
        IDs[addr] = user;
        IDs[addr].hl.hashes.push(_hashKey);
        IDs[addr].hl.verifies.push(false);
        emit NewUserRegister(addr, _hashKey);
        return true;
    }

    function getUserInfo(address addr)
    public
    view
    returns(address, string, bytes32, bytes32[], bool[]){
        return (IDs[addr].useId,
            IDs[addr].publicKey,
            IDs[addr].baseHash.hash,
            IDs[addr].hl.hashes,
            IDs[addr].hl.verifies);
    }

    function addNewIdentity(bytes32 hashKey, bytes _identity, bytes _issuer)
    public
    payable
    returns(bool){
        require(IDs[msg.sender].useId != 0); // registered user
        uint index = unregister.push(hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index);
        DataSet[hashKey] = ud;
        IDs[msg.sender].hl.hashes.push(hashKey);
        IDs[msg.sender].hl.verifies.push(false);
        emit NewIdentity(msg.sender, hashKey);
        return true;
    }

    function getBaseData(address addr)
    public
    view
    returns(bytes32, bool){
        Hash memory h = IDs[addr].baseHash;
        return (h.hash, h.verify);
    }

    function getHashData(bytes32 hash)
    public
    view
    returns(bytes, bytes, bool){
        UseData memory ud = DataSet[hash];
        return (ud.identity, ud.issuer, ud.verify);
    }

    function getUnregisterHash()
    public
    view
    returns(bytes32[]){
        return unregister;
    }

    function verifyBase(address addr)
    public
    //onlySigner
    returns(bool){
        require(IDs[addr].useId != 0);
        IDs[addr].baseHash.verify = true;
        bytes32 h = bytes32(IDs[addr].baseHash.hash);
        DataSet[h].verify = true;
        for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
            if(h == IDs[addr].hl.hashes[i]) {
                IDs[addr].hl.verifies[i] = true;
                return true;
            }
        }
        return false;
    }

    function verifyHash(address addr, bytes32 hash)
    public
    //onlySigner
    returns(bool){
        require(IDs[addr].useId != 0);
        DataSet[hash].verify = true;
        for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
            if(hash == IDs[addr].hl.hashes[i]){
                IDs[addr].hl.verifies[i] = true;
                unregister[DataSet[hash].index] = unregister[unregister.length - 1];        // move the last element to the index
                DataSet[unregister[unregister.length - 1]].index = DataSet[hash].index;     // update former last emement's index
                unregister.length--;
                return true;
            }
        }
        return false;
    }
}