// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import {MyVault} from "../src/MyVault.sol";
import {Forwarder} from "src/Forwarder.sol";
import {Token} from "../src/Token.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        Forwarder forwarder = Forwarder(0x9FfA2f219A0590db1452273012f97344b0f71CEB);
        Token a = new Token();
        Token b = new Token();
        a.mint();
        b.mint();

        MyVault vault = new MyVault(address(forwarder), address(a), address(b));

        a.approve(address(vault), type(uint256).max);
        b.approve(address(vault), type(uint256).max);

        vault.deposit(address(a), 100 * 10 ** 18);
        vault.deposit(address(b), 100 * 10 ** 18);

        vm.stopBroadcast();
    }
}

// Forwarder: 0x9FfA2f219A0590db1452273012f97344b0f71CEB
// Token A: 0x2A24Fda81786fbCFCb43aA7DaBa2F34BF6115383
// Token B: 0xAC97A7333982A170A3512bE4Ccb6A25d06004E63
// MyVault: 0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae
