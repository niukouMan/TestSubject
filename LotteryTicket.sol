pragma solidity 0.6.0;

/**
 * @title SafeMath
 * @dev Unsigned math operations with safety checks that revert on error
 */
library SafeMath {
    /**
     * @dev Multiplies two unsigned integers, reverts on overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath#mul: OVERFLOW");

        return c;
    }

    /**
     * @dev Integer division of two unsigned integers truncating the quotient, reverts on division by zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath#div: DIVISION_BY_ZERO");
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Subtracts two unsigned integers, reverts on overflow (i.e. if subtrahend is greater than minuend).
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath#sub: UNDERFLOW");
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Adds two unsigned integers, reverts on overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath#add: OVERFLOW");


        return c;
    }

    /**
     * @dev Divides two unsigned integers and returns the remainder (unsigned integer modulo),
     * reverts when dividing by zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath#mod: DIVISION_BY_ZERO");
        return a % b;
    }
}


// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false
library TransferHelper {
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        // solium-disable-next-line
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x095ea7b3, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "TransferHelper: APPROVE_FAILED"
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        // solium-disable-next-line
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "TransferHelper: TRANSFER_FAILED"
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        // solium-disable-next-line
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "TransferHelper: TRANSFER_FROM_FAILED"
        );
    }

    function safeTransferETH(address to, uint256 value) internal {
        // solium-disable-next-line
        (bool success, ) = to.call.value(value)(new bytes(0));
        require(success, "TransferHelper: ETH_TRANSFER_FAILED");
    }
}

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    //function _msgData() internal view virtual returns (bytes calldata) {
    //    this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
    //    return msg.data;
   // }
}

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping(address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account)
    internal
    view
    returns (bool)
    {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}


/**
 * @title WhitelistAdminRole
 * @dev WhitelistAdmins are responsible for assigning and removing Whitelisted accounts.
 */
contract WhitelistAdminRole is Context {
    using Roles for Roles.Role;

    event WhitelistAdminAdded(address indexed account);
    event WhitelistAdminRemoved(address indexed account);

    Roles.Role private _whitelistAdmins;

    constructor() internal {
        _addWhitelistAdmin(_msgSender());
    }

    modifier onlyWhitelistAdmin() {
        require(
            isWhitelistAdmin(_msgSender()),
            "WhitelistAdminRole: caller does not have the WhitelistAdmin role"
        );
        _;
    }

    function isWhitelistAdmin(address account) public view returns (bool) {
        return _whitelistAdmins.has(account);
    }

    function addWhitelistAdmin(address account) public onlyWhitelistAdmin {
        _addWhitelistAdmin(account);
    }

    function renounceWhitelistAdmin() public {
        _removeWhitelistAdmin(_msgSender());
    }

    function _addWhitelistAdmin(address account) internal {
        _whitelistAdmins.add(account);
        emit WhitelistAdminAdded(account);
    }

    function _removeWhitelistAdmin(address account) internal {
        _whitelistAdmins.remove(account);
        emit WhitelistAdminRemoved(account);
    }
}


contract LotteryTicket is WhitelistAdminRole{

    using SafeMath for uint256;

    //event
    event AddPool(address indexed user, uint256 indexed pid);
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Open(address indexed user, uint256 indexed pid,uint256 num);
    event EmergencyWithdraw( address indexed user, uint256 amount); //紧急情况

    //奖池信息
    struct PoolInfo{
        uint256 totalBonus;//总金额
        uint256 startBlock;//开始区块号
        uint256 endBlock;  //结束区块号
        bool isEnd;        //是否结束
    }

    //用户信息
    struct UserInfo {
        uint256 amount; // 用户提供了多少
        uint32 num;
    }

    //奖池集合
    PoolInfo[] public poolInfo;
    //池子ID=>用户地址=>用户信息 的映射
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    //奖池里投注用户列表
    mapping(uint256 =>address[]) public addressMap;
    //待提现
    uint256 unWithdraw;

     //新建奖池
     function addPool( uint256 startBlock, uint256 endBlock) public onlyWhitelistAdmin {
       require(endBlock-startBlock>1,"");
       // 池子信息推入池子数组
        poolInfo.push(
            PoolInfo({
                totalBonus: 0,
                startBlock: startBlock,
                endBlock: endBlock,
                isEnd: false
            })
        );
        emit AddPool(msg.sender,poolInfo.length);
     }

    //投注
    function deposit( uint256 pid,uint32 num) public payable{
      require(msg.value>0,"amount must grater than zero");
      require(pid<poolInfo.length,"not found this pool");
      PoolInfo storage poolInfo = poolInfo[pid];
      require(poolInfo.isEnd == false,"this pool is end");
      require(block.number>poolInfo.startBlock,"this pool not start");
      require(block.number<poolInfo.endBlock,"this pool is end");
      UserInfo storage user = userInfo[pid][msg.sender];
      if(user.num>0){
          require(user.num == num,"");
      }else{
          addressMap[pid].push(msg.sender);
      }
      user.amount += msg.value;
      user.num = num;
      poolInfo.totalBonus += msg.value;
      emit Deposit(msg.sender, pid, msg.value);
    }

    //开奖  任何人都可以调用开奖方法
    function open(uint256 pid) public{
        PoolInfo storage poolInfo = poolInfo[pid];
        uint256 currentBlock = block.number;
        require(currentBlock>poolInfo.endBlock,"this pool not end");
        //优化从预言机VRF获取随机数
        //生成随机的开奖号码
        uint256 luckNum = uint256(keccak256(abi.encodePacked(block.difficulty,now)));
        luckNum = luckNum % 1000;
        address[] memory addressList = addressMap[pid];
        address[] memory rewardAddress = new address[](addressList.length);
        uint256 index = 0;
        for(uint256 i=0; i<addressList.length ; i++){
            UserInfo storage user = userInfo[pid][msg.sender];
            if(user.num == luckNum){
                rewardAddress[index] = addressList[i];
                index++;
            }
        }

        if(index > 0){
            //奖励给用户
           uint256 reward = poolInfo.totalBonus/rewardAddress.length;
           for(uint256 i = 0;i<rewardAddress.length;i++){
              address winerAddress = rewardAddress[i];
              TransferHelper.safeTransferETH(winerAddress,reward);
           }
        }else{
            unWithdraw+=poolInfo.totalBonus;
        }
        poolInfo.isEnd = true;
        emit Open(msg.sender,pid,luckNum);
    }

    //管理员提现
    function WithdrawAward(uint256 pid) public onlyWhitelistAdmin{
        TransferHelper.safeTransferETH(msg.sender, unWithdraw);
        unWithdraw = 0;
        emit EmergencyWithdraw(msg.sender,unWithdraw);
    }

}
