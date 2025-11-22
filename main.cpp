/* 
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "Timer.h"
#include "Vanity.h"
#include "SECP256k1.h"
#include <fstream>
#include <string>
#include <string.h>
#include <stdexcept>
#include "hash/sha512.h"
#include "hash/sha256.h"
/* -----------------------------------------------------------------------
 * Colour definitions for improved CLI output.  These ANSI escape codes
 * provide colourised and emphasised text on capable terminals.  If the
 * output device does not support ANSI colours, these codes will be
 * ignored by the terminal and the text will render plainly.
 *
 * Colours are used throughout this file for headings, usage messages and
 * error reporting to make the output easier to read.  Feel free to tweak
 * or extend these definitions as needed.
 */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BLUE    "\033[34m"
#define CLR_MAGENTA "\033[35m"
#define CLR_CYAN    "\033[36m"

#define RELEASE "1.19"

using namespace std;

// ------------------------------------------------------------------------------------------

/* 
 * Print a detailed and colourful usage message for VanitySearch.  This
 * function has been reworked to include a version banner, clear headings
 * and concise option descriptions.  Colours highlight the structure of
 * the information for easier reading.  After printing the message the
 * process exits to avoid falling back into the main execution path.
 */
void printUsage() {
  // Banner with version information
  printf("%s%sVanitySearch v%s%s\n\n", CLR_BOLD, CLR_CYAN, RELEASE, CLR_RESET);
  // Top level usage line
  printf("%sUsage:%s VanitySearch [options] [prefix]\n\n", CLR_YELLOW, CLR_RESET);
  printf("  %s[prefix]%s  Prefix to search (can contain wildcards '?' or '*')\n\n",
         CLR_GREEN, CLR_RESET);

  // Options section heading
  printf("%sOptions:%s\n", CLR_YELLOW, CLR_RESET);
  printf("  %s-v%s        Print the program version\n", CLR_GREEN, CLR_RESET);
  printf("  %s-u%s        Search uncompressed addresses\n", CLR_GREEN, CLR_RESET);
  printf("  %s-b%s        Search both uncompressed and compressed addresses\n", CLR_GREEN, CLR_RESET);
  printf("  %s-c%s        Case-insensitive search\n", CLR_GREEN, CLR_RESET);
  printf("  %s-gpu%s      Enable GPU calculation\n", CLR_GREEN, CLR_RESET);
  printf("  %s-stop%s     Stop when all prefixes are found\n", CLR_GREEN, CLR_RESET);
  printf("  %s-i%s file   Load prefixes from the specified file\n", CLR_GREEN, CLR_RESET);
  printf("  %s-o%s file   Write found addresses and keys to file\n", CLR_GREEN, CLR_RESET);
  printf("  %s-gpuId%s ids  Comma separated list of GPU device IDs to use\n", CLR_GREEN, CLR_RESET);
  printf("  %s-g%s x,y,...  Specify GPU kernel grid sizes (pairs per GPU)\n", CLR_GREEN, CLR_RESET);
  printf("  %s-m%s value  Maximum number of prefixes found per kernel call\n", CLR_GREEN, CLR_RESET);
  printf("  %s-s%s seed   Use a deterministic seed for the base key\n", CLR_GREEN, CLR_RESET);
  printf("  %s-ps%s seed  Use a seed combined with a cryptographically secure random seed\n", CLR_GREEN, CLR_RESET);
  printf("  %s-t%s n      Number of CPU threads (default: number of cores)\n", CLR_GREEN, CLR_RESET);
  printf("  %s-nosse%s    Disable SSE hash functions\n", CLR_GREEN, CLR_RESET);
  printf("  %s-l%s        List CUDA-enabled devices\n", CLR_GREEN, CLR_RESET);
  printf("  %s-check%s    Validate CPU/GPU kernels against CPU implementation\n", CLR_GREEN, CLR_RESET);
  printf("  %s-cp%s priv  Compute public key from private key (hex or WIF)\n", CLR_GREEN, CLR_RESET);
  printf("  %s-ca%s pub   Compute address from public key (hex)\n", CLR_GREEN, CLR_RESET);
  printf("  %s-kp%s       Generate a key pair from the provided seed\n", CLR_GREEN, CLR_RESET);
  printf("  %s-rp%s priv file  Reconstruct final private key from partial key info\n", CLR_GREEN, CLR_RESET);
  printf("  %s-sp%s pub   Start search using the specified public key (split-key mode)\n", CLR_GREEN, CLR_RESET);
  printf("  %s-r%s value  Rekey interval in MegaKeys (default disabled)\n\n", CLR_GREEN, CLR_RESET);

  // Footer with hint for further help
  printf("%sExample:%s VanitySearch -gpu -stop 1Test\n\n", CLR_YELLOW, CLR_RESET);
  exit(0);
}

// ------------------------------------------------------------------------------------------

int getInt(string name,char *v) {

  int r;

  try {

    r = std::stoi(string(v));

  } catch(std::invalid_argument&) {

    printf("%sInvalid %s argument, number expected%s\n", CLR_RED, name.c_str(), CLR_RESET);
    exit(-1);

  }

  return r;

}

// ------------------------------------------------------------------------------------------

void getInts(string name,vector<int> &tokens, const string &text, char sep) {

  size_t start = 0, end = 0;
  tokens.clear();
  int item;

  try {

    while ((end = text.find(sep, start)) != string::npos) {
      item = std::stoi(text.substr(start, end - start));
      tokens.push_back(item);
      start = end + 1;
    }

    item = std::stoi(text.substr(start));
    tokens.push_back(item);

  } catch(std::invalid_argument &) {

    printf("%sInvalid %s argument, number expected%s\n", CLR_RED, name.c_str(), CLR_RESET);
    exit(-1);

  }

}

// ------------------------------------------------------------------------------------------

void parseFile(string fileName, vector<string> &lines) {

  // Get file size
  FILE *fp = fopen(fileName.c_str(), "rb");
  if (fp == NULL) {
    printf("%sError: Cannot open %s %s%s\n", CLR_RED, fileName.c_str(), strerror(errno), CLR_RESET);
    exit(-1);
  }
  fseek(fp, 0L, SEEK_END);
  size_t sz = ftell(fp);
  size_t nbAddr = sz / 33; /* Upper approximation */
  bool loaddingProgress = sz > 100000;
  fclose(fp);

  // Parse file
  int nbLine = 0;
  string line;
  ifstream inFile(fileName);
  lines.reserve(nbAddr);
  while (getline(inFile, line)) {

    // Remove ending \r\n
    int l = (int)line.length() - 1;
    while (l >= 0 && isspace(line.at(l))) {
      line.pop_back();
      l--;
    }

    if (line.length() > 0) {
      lines.push_back(line);
      nbLine++;
      if (loaddingProgress) {
        if ((nbLine % 50000) == 0)
          printf("[Loading input file %5.1f%%]\r", ((double)nbLine*100.0) / ((double)(nbAddr)*33.0 / 34.0));
      }
    }

  }

  if (loaddingProgress)
    printf("[Loading input file 100.0%%]\n");

}

// ------------------------------------------------------------------------------------------

void generateKeyPair(Secp256K1 *secp, string seed, int searchMode,bool paranoiacSeed) {

  if (seed.length() < 8) {
    printf("%sError: Use a seed of at least 8 characters to generate a key pair%s\n", CLR_RED, CLR_RESET);
    printf("Ex: VanitySearch -s \"A Strong Password\" -kp\n");
    exit(-1);
  }

  if(paranoiacSeed)
    seed = seed + Timer::getSeed(32);

  if (searchMode == SEARCH_BOTH) {
    printf("%sError: Use compressed or uncompressed to generate a key pair%s\n", CLR_RED, CLR_RESET);
    exit(-1);
  }

  bool compressed = (searchMode == SEARCH_COMPRESSED);

  string salt = "VanitySearch";
  unsigned char hseed[64];
  pbkdf2_hmac_sha512(hseed, 64, (const uint8_t *)seed.c_str(), seed.length(),
    (const uint8_t *)salt.c_str(), salt.length(),
    2048);

  Int privKey;
  privKey.SetInt32(0);
  sha256(hseed, 64, (unsigned char *)privKey.bits64);
  Point p = secp->ComputePublicKey(&privKey);
  printf("Priv : %s\n", secp->GetPrivAddress(compressed,privKey).c_str());
  printf("Pub  : %s\n", secp->GetPublicKeyHex(compressed,p).c_str());

}

// ------------------------------------------------------------------------------------------

void outputAdd(string outputFile, int addrType, string addr, string pAddr, string pAddrHex) {

  FILE *f = stdout;
  bool needToClose = false;

  if (outputFile.length() > 0) {
    f = fopen(outputFile.c_str(), "a");
    if (f == NULL) {
      printf("%sCannot open %s for writing%s\n", CLR_RED, outputFile.c_str(), CLR_RESET);
      f = stdout;
    } else {
      needToClose = true;
    }
  }

  fprintf(f, "\nPub Addr: %s\n", addr.c_str());


  switch (addrType) {
  case P2PKH:
    fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
    break;
  case P2SH:
    fprintf(f, "Priv (WIF): p2wpkh-p2sh:%s\n", pAddr.c_str());
    break;
  case BECH32:
    fprintf(f, "Priv (WIF): p2wpkh:%s\n", pAddr.c_str());
    break;
  }
  fprintf(f, "Priv (HEX): 0x%s\n", pAddrHex.c_str());

  if (needToClose)
    fclose(f);

}

// ------------------------------------------------------------------------------------------
#define CHECK_ADDR()                                           \
  fullPriv.ModAddK1order(&e, &partialPrivKey);                 \
  p = secp->ComputePublicKey(&fullPriv);                       \
  cAddr = secp->GetAddress(addrType, compressed, p);           \
  if (cAddr == addr) {                                         \
    found = true;                                              \
    string pAddr = secp->GetPrivAddress(compressed, fullPriv); \
    string pAddrHex = fullPriv.GetBase16();                    \
    outputAdd(outputFile, addrType, addr, pAddr, pAddrHex);    \
  }

void reconstructAdd(Secp256K1 *secp, string fileName, string outputFile, string privAddr) {

  bool compressed;
  int addrType;
  Int lambda;
  Int lambda2;
  lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
  lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");

  Int privKey = secp->DecodePrivateKey((char *)privAddr.c_str(),&compressed);
  if(privKey.IsNegative())
    exit(-1);

  vector<string> lines;
  parseFile(fileName,lines);

  for (int i = 0; i < (int)lines.size(); i+=2) {

    string addr;
    string partialPrivAddr;

    if (lines[i].substr(0, 12) == "PubAddress: ") {

      addr = lines[i].substr(12);

      switch (addr.data()[0]) {
      case '1':
        addrType = P2PKH; break;
      case '3':
        addrType = P2SH; break;
      case 'b':
      case 'B':
        addrType = BECH32; break;
      default:
        printf("%sInvalid partialkey info file at line %d%s\n", CLR_RED, i, CLR_RESET);
        printf("%s%s Address format not supported%s\n", CLR_RED, addr.c_str(), CLR_RESET);
        continue;
      }

    } else {
      printf("%sInvalid partialkey info file at line %d (\"PubAddress: \" expected)%s\n", CLR_RED,i, CLR_RESET);
      exit(-1);
    }

    if (lines[i+1].substr(0, 13) == "PartialPriv: ") {
      partialPrivAddr = lines[i+1].substr(13);
    } else {
      printf("%sInvalid partialkey info file at line %d (\"PartialPriv: \" expected)%s\n", CLR_RED, i, CLR_RESET);
      exit(-1);
    }

    bool partialMode;
    Int partialPrivKey = secp->DecodePrivateKey((char *)partialPrivAddr.c_str(), &partialMode);
    if (privKey.IsNegative()) {
      printf("%sInvalid partialkey info file at line %d%s\n", CLR_RED, i, CLR_RESET);
      exit(-1);
    }

    if (partialMode != compressed) {

      printf("%sWarning, Invalid partialkey at line %d (Wrong compression mode, ignoring key)%s\n", CLR_YELLOW, i, CLR_RESET);
      continue;

    } else {

      // Reconstruct the address
      Int fullPriv;
      Point p;
      Int e;
      string cAddr;
      bool found = false;

      // No sym, no endo
      e.Set(&privKey);
      CHECK_ADDR();

      // No sym, endo 1
      e.Set(&privKey);
      e.ModMulK1order(&lambda);
      CHECK_ADDR();

      // No sym, endo 2
      e.Set(&privKey);
      e.ModMulK1order(&lambda2);
      CHECK_ADDR();

      // sym, no endo
      e.Set(&privKey);
      e.Neg();
      e.Add(&secp->order);
      CHECK_ADDR();

      // sym, endo 1
      e.Set(&privKey);
      e.ModMulK1order(&lambda);
      e.Neg();
      e.Add(&secp->order);
      CHECK_ADDR();

      // sym, endo 2
      e.Set(&privKey);
      e.ModMulK1order(&lambda2);
      e.Neg();
      e.Add(&secp->order);
      CHECK_ADDR();

      if (!found) {
        printf("%sUnable to reconstruct final key from partialkey line %d%s\n Addr: %s\n PartKey: %s\n",
          CLR_RED, i, CLR_RESET, addr.c_str(),partialPrivAddr.c_str());
      }

    }

  }

}

// ------------------------------------------------------------------------------------------

int main(int argc, char* argv[]) {

  // Global Init
  Timer::Init();
  rseed(Timer::getSeed32());

  // Init SecpK1
  Secp256K1 *secp = new Secp256K1();
  secp->Init();

  // Browse arguments
  if (argc < 2) {
    printf("%sError: No arguments (use -h for help)%s\n", CLR_RED, CLR_RESET);
    exit(-1);
  }

  int a = 1;
  bool gpuEnable = false;
  bool stop = false;
  int searchMode = SEARCH_COMPRESSED;
  vector<int> gpuId = {0};
  vector<int> gridSize;
  string seed = "";
  vector<string> prefix;
  string outputFile = "";
  int nbCPUThread = Timer::getCoreNumber();
  bool tSpecified = false;
  bool sse = true;
  uint32_t maxFound = 65536;
  uint64_t rekey = 0;
  Point startPuKey;
  startPuKey.Clear();
  bool startPubKeyCompressed;
  bool caseSensitive = true;
  bool paranoiacSeed = false;

  while (a < argc) {

    if (strcmp(argv[a], "-gpu")==0) {
      gpuEnable = true;
      a++;
    } else if (strcmp(argv[a], "-gpuId")==0) {
      a++;
      getInts("gpuId",gpuId,string(argv[a]),',');
      a++;
    } else if (strcmp(argv[a], "-stop") == 0) {
      stop = true;
      a++;
    } else if (strcmp(argv[a], "-c") == 0) {
      caseSensitive = false;
      a++;
    } else if (strcmp(argv[a], "-v") == 0) {
      printf("%s\n",RELEASE);
      exit(0);
    } else if (strcmp(argv[a], "-check") == 0) {

      Int::Check();
      secp->Check();

#ifdef WITHGPU
      if (gridSize.size() == 0) {
        gridSize.push_back(-1);
        gridSize.push_back(128);
      }
      GPUEngine g(gridSize[0],gridSize[1],gpuId[0],maxFound,false);
      g.SetSearchMode(searchMode);
      g.Check(secp);
#else
      printf("%sGPU code not compiled, use -DWITHGPU when compiling.%s\n", CLR_RED, CLR_RESET);
#endif
      exit(0);
    } else if (strcmp(argv[a], "-l") == 0) {

#ifdef WITHGPU
      GPUEngine::PrintCudaInfo();
#else
      printf("%sGPU code not compiled, use -DWITHGPU when compiling.%s\n", CLR_RED, CLR_RESET);
#endif
      exit(0);

    } else if (strcmp(argv[a], "-kp") == 0) {
      generateKeyPair(secp,seed,searchMode,paranoiacSeed);
      exit(0);
    } else if (strcmp(argv[a], "-sp") == 0) {
      a++;
      string pub = string(argv[a]);
      startPuKey = secp->ParsePublicKeyHex(pub, startPubKeyCompressed);
      a++;
    } else if(strcmp(argv[a],"-ca") == 0) {
      a++;
      string pub = string(argv[a]);
      bool isComp;
      Point p = secp->ParsePublicKeyHex(pub,isComp);
      printf("Addr (P2PKH): %s\n",secp->GetAddress(P2PKH,isComp,p).c_str());
      printf("Addr (P2SH): %s\n",secp->GetAddress(P2SH,isComp,p).c_str());
      printf("Addr (BECH32): %s\n",secp->GetAddress(BECH32,isComp,p).c_str());
      exit(0);
    } else if (strcmp(argv[a], "-cp") == 0) {
      a++;
      string priv = string(argv[a]);
      Int k;
      bool isComp = true;
      if(priv[0]=='5' || priv[0] == 'K' || priv[0] == 'L') {
        k = secp->DecodePrivateKey((char *)priv.c_str(),&isComp);
      } else {
        k.SetBase16(argv[a]);
      }
      Point p = secp->ComputePublicKey(&k);
      printf("PrivAddr: p2pkh:%s\n",secp->GetPrivAddress(isComp,k).c_str());
      printf("PubKey: %s\n",secp->GetPublicKeyHex(isComp,p).c_str());
      printf("Addr (P2PKH): %s\n", secp->GetAddress(P2PKH,isComp,p).c_str());
      printf("Addr (P2SH): %s\n", secp->GetAddress(P2SH,isComp,p).c_str());
      printf("Addr (BECH32): %s\n", secp->GetAddress(BECH32,isComp,p).c_str());
      exit(0);
    } else if (strcmp(argv[a], "-rp") == 0) {
      a++;
      string priv = string(argv[a]);
      a++;
      string file = string(argv[a]);
      a++;
      reconstructAdd(secp,file,outputFile,priv);
      exit(0);
    } else if (strcmp(argv[a], "-u") == 0) {
      searchMode = SEARCH_UNCOMPRESSED;
      a++;
    } else if (strcmp(argv[a], "-b") == 0) {
      searchMode = SEARCH_BOTH;
      a++;
    } else if (strcmp(argv[a], "-nosse") == 0) {
      sse = false;
      a++;
    } else if (strcmp(argv[a], "-g") == 0) {
      a++;
      getInts("gridSize",gridSize,string(argv[a]),',');
      a++;
    } else if (strcmp(argv[a], "-s") == 0) {
      a++;
      seed = string(argv[a]);
      a++;
    } else if (strcmp(argv[a], "-ps") == 0) {
      a++;
      seed = string(argv[a]);
      paranoiacSeed = true;
      a++;
    } else if (strcmp(argv[a], "-o") == 0) {
      a++;
      outputFile = string(argv[a]);
      a++;
    } else if (strcmp(argv[a], "-i") == 0) {
      a++;
      parseFile(string(argv[a]),prefix);
      a++;
    } else if (strcmp(argv[a], "-t") == 0) {
      a++;
      nbCPUThread = getInt("nbCPUThread",argv[a]);
      a++;
      tSpecified = true;
    } else if (strcmp(argv[a], "-m") == 0) {
      a++;
      maxFound = getInt("maxFound", argv[a]);
      a++;
    } else if (strcmp(argv[a], "-r") == 0) {
      a++;
      rekey = (uint64_t)getInt("rekey", argv[a]);
      a++;
    } else if (strcmp(argv[a], "-h") == 0) {
      printUsage();
    } else if (a == argc - 1) {
      prefix.push_back(string(argv[a]));
      a++;
    } else {
      printf("%sUnexpected %s argument%s\n", CLR_RED, argv[a], CLR_RESET);
      exit(-1);
    }

  }

  printf("VanitySearch v" RELEASE "\n");

  if(gridSize.size()==0) {
    for (int i = 0; i < (int)gpuId.size(); i++) {
      gridSize.push_back(-1);
      gridSize.push_back(128);
    }
  } else if(gridSize.size() != (int)gpuId.size()*2) {
    printf("%sInvalid gridSize or gpuId argument, must have coherent size%s\n", CLR_RED, CLR_RESET);
    exit(-1);
  }

  // Let one CPU core free per gpu is gpu is enabled
  // It will avoid to hang the system
  if( !tSpecified && nbCPUThread>1 && gpuEnable)
    nbCPUThread-=(int)gpuId.size();
  if(nbCPUThread<0)
    nbCPUThread = 0;

  // If a starting public key is specified, force the search mode according to the key
  if (!startPuKey.isZero()) {
    searchMode = (startPubKeyCompressed)?SEARCH_COMPRESSED:SEARCH_UNCOMPRESSED;
  }

  VanitySearch *v = new VanitySearch(secp, prefix, seed, searchMode, gpuEnable, stop, outputFile, sse,
    maxFound, rekey, caseSensitive, startPuKey, paranoiacSeed);
  v->Search(nbCPUThread,gpuId,gridSize);

  return 0;
}
