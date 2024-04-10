// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract Token is ERC20("Token", "TK") {
    bool _hasMinted;

    function mint() external payable {
        require(_hasMinted == false);
        _hasMinted = true;
        _mint(msg.sender, 100 * 10 ** 18);
    }
}
