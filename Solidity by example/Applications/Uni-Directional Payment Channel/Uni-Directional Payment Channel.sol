// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ECDSA.sol";

contract ReentrancyGuard {
    bool private locked;

    modifier guard() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }
}

contract UniDirectionalPaymentChannel is ReentrancyGuard {
    using ECDSA for bytes32;

    address payable public sender;
    address payable public receiver;

    uint256 private constant DURATION = 7 * 24 * 60 * 60;
    uint256 public expiresAt;

    constructor(address payable _receiver) payable {
        require(_receiver != address(0), "receiver = zero address");
        sender = payable(msg.sender);
        receiver = _receiver;
        expiresAt = block.timestamp + DURATION;
    }

    function _getHash(uint256 _amount) private view returns (bytes32) {
        // NOTE: sign with address of this contract to protect agains
        // replay attack on other contracts
        return keccak256(abi.encodePacked(address(this), _amount));
    }

    function getHash(uint256 _amount) external view returns (bytes32) {
        return _getHash(_amount);
    }

    function _getEthSignedHash(uint256 _amount)
        private
        view
        returns (bytes32)
    {
        return _getHash(_amount).toEthSignedMessageHash();
    }

    function getEthSignedHash(uint256 _amount)
        external
        view
        returns (bytes32)
    {
        return _getEthSignedHash(_amount);
    }

    function _verify(uint256 _amount, bytes memory _sig)
        private
        view
        returns (bool)
    {
        return _getEthSignedHash(_amount).recover(_sig) == sender;
    }

    function verify(uint256 _amount, bytes memory _sig)
        external
        view
        returns (bool)
    {
        return _verify(_amount, _sig);
    }

    function close(uint256 _amount, bytes memory _sig) external guard {
        require(msg.sender == receiver, "!receiver");
        require(_verify(_amount, _sig), "invalid sig");

        (bool sent,) = receiver.call{value: _amount}("");
        require(sent, "Failed to send Ether");
        selfdestruct(sender);
    }

    function cancel() external {
        require(msg.sender == sender, "!sender");
        require(block.timestamp >= expiresAt, "!expired");
        selfdestruct(sender);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/ECDSA.sol)

library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    function tryRecover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address, RecoverError)
    {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return tryRecover(hash, r, vs);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    function recover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs)
        internal
        pure
        returns (address, RecoverError)
    {
        bytes32 s = vs
            & bytes32(
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            );
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    function recover(bytes32 hash, bytes32 r, bytes32 vs)
        internal
        pure
        returns (address)
    {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (address, RecoverError)
    {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (
            uint256(s)
                > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (address)
    {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    function toEthSignedMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32)
    {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }
}
