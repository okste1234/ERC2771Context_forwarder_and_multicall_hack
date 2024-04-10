// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// import {Token} from "src/Token.sol";
import {ERC2771Context} from "lib/openzeppelin-contracts/contracts/metatx/ERC2771Context.sol";
import {Multicall} from "lib/openzeppelin-contracts/contracts/utils/Multicall.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {Forwarder} from "src/Forwarder.sol";

contract MyVault is Multicall, ERC2771Context {
    address public owner;
    mapping(address token => uint256 amount) public myBalanceOf;
    address public forwarder;
    IERC20 a;
    IERC20 b;
    uint256 count;

    constructor(address _forwarder, address a_, address b_) ERC2771Context(_forwarder) {
        owner = _msgSender();
        forwarder = _forwarder;
        a = IERC20(a_);
        b = IERC20(b_);
    }

    modifier onlyOwner() {
        require(_msgSender() == owner, "not authorized");
        _;
    }

    modifier onlyOnce(address receiver) {
        uint256 nonce = Forwarder(forwarder).getNonce(receiver);
        if (count == 0) {
            count = nonce;
        }

        if (count > nonce) {
            count = 0;
            revert();
        }
        _;
    }

    function deposit(address token, uint256 amount) external onlyOwner {
        IERC20(token).transferFrom(owner, address(this), amount);
        myBalanceOf[token] += amount;
    }

    function withdraw(address token) external {
        uint256 total = IERC20(token).balanceOf(address(this));
        myBalanceOf[token] -= total;
        IERC20(token).transfer(owner, total);
    }

    function withdrawTo(address token, address receiver, uint256 amount) external onlyOwner onlyOnce(receiver) {
        myBalanceOf[token] -= amount;
        IERC20(token).transfer(receiver, amount);
    }

    function confirmHack() external view returns (bool) {
        return myBalanceOf[address(a)] == 0 && myBalanceOf[address(b)] == 0 && a.balanceOf(owner) == 0
            && b.balanceOf(owner) == 0;
    }
}
