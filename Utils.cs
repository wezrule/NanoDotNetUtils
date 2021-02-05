using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Security.Cryptography;
using Blake2Core;
using Chaos.NaCl;

namespace NanoDotNetUtils
{
  public class PublicKey
  {
    public PublicKey(byte[] bytes)
    {
      Bytes = bytes;
    }

    public string Key => Utils.ByteArrayToHex(Bytes);

    public byte[] Bytes { get; }

    private string address;
    public string Address
    {
      get
      {
        if (address == null)
        {
          address = Utils.PublicKeyToAddress(Bytes);
        }
        return address;
      }
    }
    public override int GetHashCode()
    {
      return System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(Bytes);
    }
  }

  public static class Utils
  {
    private static Dictionary<char, string> nano_addressEncoding;
    private static Dictionary<string, char> nano_addressDecoding;

    public static byte[] CreateSeed()
    {
      RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
      byte[] randomNumber = new byte[32];
      rngCsp.GetBytes(randomNumber);
      return randomNumber;
    }

    public static PublicKey PublicKeyFromPrivateKey(byte[] privateKey)
    {
      return new PublicKey(Ed25519.PublicKeyFromSeed(privateKey));
    }

    public static PublicKey PublicKeyFromPrivateKey(string privateKey)
    {
      return PublicKeyFromPrivateKey(HexStringToByteArray(privateKey));
    }

    static Utils()
    {
      nano_addressEncoding = new Dictionary<char, string>();
      nano_addressDecoding = new Dictionary<string, char>();

      var i = 0;
      foreach (var validAddressChar in "13456789abcdefghijkmnopqrstuwxyz")
      {
        nano_addressEncoding[validAddressChar] = Convert.ToString(i, 2).PadLeft(5, '0');
        nano_addressDecoding[Convert.ToString(i, 2).PadLeft(5, '0')] = validAddressChar;
        i++;
      }
    }

    public static byte[] HexStringToByteArray(string hex)
    {
      return Enumerable.Range(0, hex.Length)
                           .Where(x => x % 2 == 0)
                           .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                           .ToArray();
    }

    public static string ByteArrayToHex(byte[] bytes)
    {
      var hex = new StringBuilder();
      for (int j = 0; j < bytes.Length; j++)
      {
        hex.AppendFormat("{0:X2}", bytes[j]);
      }
      return hex.ToString();
    }

    public static string PublicKeyToAddress(byte[] publicKey)
    {
      var address = "nano_" + NanoEncode(publicKey);

      var blake = Blake2B.Create(new Blake2BConfig() { OutputSizeInBytes = 5 });
      blake.Init();
      blake.Update(publicKey);
      var checksumBytes = blake.Finish();

      address += NanoEncode(checksumBytes.Reverse().ToArray(), false);

      return address;

    }

    private static string NanoEncode(byte[] bytes, bool padZeros = true)
    {
      var binaryString = padZeros ? "0000" : "";
      for (int i = 0; i < bytes.Length; i++)
      {
        binaryString += Convert.ToString(bytes[i], 2).PadLeft(8, '0');
      }

      var result = "";

      for (int i = 0; i < binaryString.Length; i += 5)
      {
        result += nano_addressDecoding[binaryString.Substring(i, 5)];
      }

      return result;
    }

    public static bool AddressIsValid(string address)
    {
      byte[] pubkeyBytes = AddressToPublicKey(address);
      if (pubkeyBytes == null)
      {
        return false;
      }

      var blake = Blake2B.Create(new Blake2BConfig() { OutputSizeInBytes = 5 });

      blake.Init();
      blake.Update(pubkeyBytes);
      var hashBytes = blake.Finish();

      // Checksum is last 8 characters, compare
      var checksum = address.Substring (address.Length - 8, 8);

      var binaryString = "";
      for (int i = 0; i < checksum.Length; i++)
      {
        // Decode each character into string representation of it's binary parts
        binaryString += nano_addressEncoding[checksum[i]];
      }

      // Convert to bytes
      var pk = new byte[5];
      for (int i = 0; i < 5; i++)
      {
        // for each byte, read the bits from the binary string
        var b = Convert.ToByte(binaryString.Substring(i * 8, 8), 2);
        pk[i] = b;
      }

      return hashBytes.SequenceEqual (pk.Reverse());
    }

    public static byte[] AddressToPublicKey(string address)
    {
      // Check length is valid
      if (address.Length != 65)
      {
        return null;
      }

      // Address must begin with nano
      if (!address.Substring(0, 5).Equals("nano_"))
      {
        return null;
      }

      // Next should start with a 1 or 3
      if (!address.Substring(5, 1).Equals("1") && !address.Substring(5, 1).Equals("3"))
      {
        return null;
      }

      // Remove nano_
      var publicKeyPart = address.Substring(5, address.Length - 8);

      var binaryString = "";
      for (int i = 0; i < publicKeyPart.Length; i++)
      {
        // Decode each character into string representation of it's binary parts
        binaryString += nano_addressEncoding[publicKeyPart[i]];
      }

      // Remove leading 4 0s
      binaryString = binaryString.Substring(4);

      // Convert to bytes
      var pk = new byte[32];
      for (int i = 0; i < 32; i++)
      {
        // for each byte, read the bits from the binary string
        var b = Convert.ToByte(binaryString.Substring(i * 8, 8), 2);
        pk[i] = b;
      }
      return pk;
    }

    public static string HashStateBlock(string accountAddress, string previousHash, string balance, string representativeAccount, string link)
    {
      var representativePublicKey = AddressToPublicKey(representativeAccount);
      var accountPublicKey = AddressToPublicKey(accountAddress);
      var previousBytes = HexStringToByteArray(previousHash);

      var balanceHex = BigInteger.Parse(balance).ToString("X");
      if (balanceHex.Length % 2 == 1)
      {
        balanceHex = "0" + balanceHex;
      }
      byte[] balanceBytes = HexStringToByteArray(balanceHex.PadLeft(32, '0'));
      var linkBytes = HexStringToByteArray(link);
      var preamble = HexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000006");

      var blake = Blake2B.Create(new Blake2BConfig() { OutputSizeInBytes = 32 });

      blake.Init();
      blake.Update(preamble);
      blake.Update(accountPublicKey);
      blake.Update(previousBytes);
      blake.Update(representativePublicKey);
      blake.Update(balanceBytes);
      blake.Update(linkBytes);

      var hashBytes = blake.Finish();
      return ByteArrayToHex(hashBytes);
    }

    public static string SignHash(string hash, byte[] privateKey)
    {
      var publicKey = Ed25519.PublicKeyFromSeed(privateKey);
      var signature = Ed25519.Sign(HexStringToByteArray(hash), Ed25519.ExpandedPrivateKeyFromSeed(privateKey));
      return ByteArrayToHex(signature);
    }
  }
}
