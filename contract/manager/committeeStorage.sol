pragma solidity ^ 0.4.24;

contract committeeStorage {
    // @notice Committee
    uint constant public MAX_COMMITTEEMAN_COUNT = 5;
    uint constant public Requirement = 3;

    uint constant public Election_cycle = 2628000;
    uint constant public Election_duration = 50000;

    bool public vote_enabled = true;

    // @dev Committee
    struct Committee {
        bool confirmed;
        address addr;
        string asymPubkey;
    }

    // @dev Election round
    struct Round {
        address[] candidate;
        mapping(address => uint) votes;    //candidate's vote count
        mapping(address => bool) voted;    //voter whether voted already

        bool selected;
        Committee[MAX_COMMITTEEMAN_COUNT] committes;

        string committeePublicKey;
        string committeePublicKey_candidate;
        mapping(address => bool) pubKeyConfirmed;
        uint confirmCount;
    }
    mapping(uint => Round) public rounds;

    // @notice In which round now
    function whichRound()
    public
    constant
    returns(uint)
    {
        return block.number/Election_cycle;
    }

    // @notice whether main account
    ///TODO: add it
    modifier isMainAccount() {
        require(true);
        _;
    }

    /****************voting*********************/
    // @notice voting now?
    modifier isVoting() {
        //require(block.number%Election_cycle <= Election_duration);
        require(vote_enabled);
        _;
    }

    // @notice not voting
    modifier notVoting() {
        //require(block.number%Election_cycle > Election_duration);
        require(!vote_enabled);
        _;
    }

    // @notice can't vote twice in one round
    modifier notVoted() {
        require(rounds[whichRound()].voted[msg.sender] == false);
        _;
    }

    // @notice committee already been selected
    modifier notSelected() {
        require(rounds[whichRound()].selected == false);
        _;
    }

    // @notice start vote or stop it
    function controlVote(bool _flag) public {
        vote_enabled = _flag;
    }
    
    function getBlockNumber() public view returns(uint) {
        return block.number;
    }

    // @notice votes
    function vote(address _candidate)
    isMainAccount
    isVoting
    notVoted
    public
    returns(bool){
        // which round
        uint roundIndex = whichRound();
        
        if(rounds[roundIndex].votes[_candidate] == 0) {
            rounds[roundIndex].candidate.push(_candidate);
        }
        rounds[roundIndex].votes[_candidate]++;

        rounds[roundIndex].voted[msg.sender] = true;
        
        // check whether candidate in committee list or not
        for(uint i=0; i<MAX_COMMITTEEMAN_COUNT;i++) {
            if(rounds[roundIndex].committes[i].addr == _candidate) {
                return true;
            }
            
            if(rounds[roundIndex].committes[i].addr == address(0)) {
                rounds[roundIndex].committes[i].addr = _candidate;
                return true;
            }
        }
        
        // sort
        reSort(roundIndex, _candidate);
        return true;
    }
    
    // do sort at each tx
    function reSort(uint _roundIndex, address _candidate)
    internal {
        // init min
        uint minIndex = 0;
        address minCandidate = rounds[_roundIndex].committes[0].addr;
        uint minVotes = rounds[_roundIndex].votes[minCandidate];

        // reindex min
        for(uint i=1; i<MAX_COMMITTEEMAN_COUNT;i++){
            minCandidate = rounds[_roundIndex].committes[i].addr;
            if(minVotes > rounds[_roundIndex].votes[minCandidate]) {
                minVotes = rounds[_roundIndex].votes[minCandidate];
                minIndex = i;
            }
        }
        minCandidate = rounds[_roundIndex].committes[minIndex].addr;
        // update 
        if (minVotes < rounds[_roundIndex].votes[_candidate]) {
            rounds[_roundIndex].committes[minIndex].addr = _candidate;
            rounds[_roundIndex].committes[minIndex].confirmed = false;
            rounds[_roundIndex].committes[minIndex].asymPubkey = "";
        }
    }
    
    // @notice get address's votes
    function getVotes(address _candidate)
    public
    constant
    returns(uint)
    {
        return rounds[whichRound()].votes[_candidate];
    }

    // @test
    function getCandidateLen()
    public
    constant
    returns(uint)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].candidate.length;
    }

    //@test
    function getCandidate(uint _index)
    public
    constant
    returns(address)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].candidate[_index];
    }

    /****************committes*********************/
    // @notice whether a committes now
    modifier isCommittee() {
        require(getCommitteeIndex() != 0xffff);
        _;
    }

    // @notice whether a committes now
    function IsCommittee()
    public
    constant
    returns(bool)
    {
        return  getCommitteeIndex() != 0xffff;
    }

    //@test
    function getCommittee(uint _index)
    public
    constant
    returns(address)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committes[_index].addr;
    }

    // @notice whether a committes now
    function getCommitteeIndex()
    public
    constant
    returns(uint)
    {
        uint roundIndex = whichRound();
        for(uint i = 0; i < rounds[roundIndex].committes.length; i++) {
        if(rounds[roundIndex].committes[i].addr == msg.sender) {
            return i;
        }
    }
        return 0xffff;
    }

    // @notice check the committee whether confirmed
    function getCommitteeConfirmStat()
    public
    constant
    returns(bool)
    {
        uint roundIndex = whichRound();
        uint committeeIndex = getCommitteeIndex();
        return rounds[roundIndex].committes[committeeIndex].confirmed;
    }

    // @notice confirm & upload whisper asymPubkey
    function confirmAndKeyUpload(string _asymPubkey)
    isCommittee
    public
    {
        uint roundIndex = whichRound();
        uint committeeIndex = getCommitteeIndex();
        rounds[roundIndex].committes[committeeIndex].confirmed = true;
        rounds[roundIndex].committes[committeeIndex].asymPubkey = _asymPubkey;
    }

    // @notice get committee asym key
    function getCommitteeAsymkey(uint index)
    public
    constant
    returns(string)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committes[index].asymPubkey;
    }

    //Check whether all committee confirmed&&uploaded
    function isEntireConfirmed()
    public
    constant
    returns(bool)
    {
        uint roundIndex = whichRound();
        for(uint i = 0; i < MAX_COMMITTEEMAN_COUNT; i++) {
        if (rounds[roundIndex].committes[i].confirmed == false) {
            return false;
        }
    }
        return true;
    }


    /*****************committeePublicKey upload & confirm********************/
    //upload committee's personal public key
    function uploadCommitteePubkey(string _pubkey)
    isCommittee
    public
    {
        uint roundIndex = whichRound();
        require(isEntireConfirmed() == true);
        rounds[roundIndex].committeePublicKey = _pubkey;
        // uint roundIndex = whichRound();
        // rounds[roundIndex].committeePublicKey_candidate = _pubkey;
        // rounds[roundIndex].pubKeyConfirmed[msg.sender] = true;
        // rounds[roundIndex].confirmCount == 1;
    }

    //confirm the committee public key
    ///TODO: Not used yet
    function confirmCommitteePubkey(string _pubkey)
    isCommittee
    public
    {
        uint roundIndex = whichRound();
        if(keccak256(abi.encodePacked(rounds[roundIndex].committeePublicKey_candidate)) != keccak256(abi.encodePacked(_pubkey))) {
            return;
        }
        rounds[roundIndex].committeePublicKey_candidate = _pubkey;
        rounds[roundIndex].pubKeyConfirmed[msg.sender] = true;
        rounds[roundIndex].confirmCount ++;

        if(rounds[roundIndex].confirmCount >= Requirement) {
            rounds[roundIndex].committeePublicKey = rounds[roundIndex].committeePublicKey_candidate;
        }
    }

    //@dev get the current committeePublicKey
    function getCommitteePubkey()
    public
    constant
    returns(string)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committeePublicKey;
    }
}
