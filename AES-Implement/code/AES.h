#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

// ECB 启用ECB加解密模式
// CBC 启用CBC加解密模式
// CTR 启用CTR加解密模式
#ifndef ECB
  #define ECB 1
#endif
#ifndef CBC
  #define CBC 1
#endif
#ifndef CTR
  #define CTR 1
#endif

// 使用AES标准
#define AES128 1
// #define AES192 1
// #define AES256 1

// 在AES标准中，每个块大小为128bit，也就是16字节
#define AES_BLOCKLEN 16 


/*
  Nb: 状态矩阵列数，在AES标准中始终为4
  Nk: 密钥长度
  Nr: 加密轮数
    +---------+--------------------+-------------------+---------+
    |   AES	  | 密钥长度（32位比特字) | 分组长度(32位比特字) | 加密轮数 |
    +---------+--------------------+-------------------+---------+
    | AES-128 |	        4	         |        4          |  	10   |
    +---------+--------------------+-------------------+---------+
    | AES-192 |	        6	         |        4          |  	12   |
    +---------+--------------------+-------------------+---------+
    | AES-256 |	        8	         |        4          |  	14   |
    +---------+--------------------+-------------------+---------+
*/
#define Nb 4
#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif


// 根据AES密码标准定义密钥长度以及它们的拓展位数（单位：字节）
#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16
    #define AES_keyExpSize 176
#endif


// S盒以及逆S盒
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif


// 每一轮的常量数组 
// Rcon[i]包含由 x 的幂 (i-1) 给出的值，即字段 GF(2^8) 中 x 的幂（x 表示为 {02}）
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// 状态矩阵
typedef uint8_t state_t[4][4];

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
  // 在ECB模式下不会使用到初始向量
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};



// 初始化函数
void AES_init_ctx(const uint8_t* sbox, struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(const uint8_t* sbox, struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

// ECB模式加解密函数
#if defined(ECB) && (ECB == 1)
// 在加解密之前，只需要AES_init_ctx，因为在ECB模式的加解密中不需要IV
// 每次加解密一个块，也就是16字节，buf长度为AES_BLOCKLEN
void AES_ECB_encrypt_buffer(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_decrypt_buffer(const uint8_t* rsbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length);

void AES_ECB_encrypt_buffer_parallel(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_decrypt_buffer_parallel(const uint8_t* rsbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CBC) && (CBC == 1)
// 在加解密之前需要AES_init_ctx和初始化IV
// 每次加解密一个块，也就是16字节，buf长度为AES_BLOCKLEN
void AES_CBC_encrypt_buffer(const uint8_t* sbox, struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(const uint8_t* rsbox, struct AES_ctx* ctx, uint8_t* buf, size_t length);
#endif 


#if defined(CTR) && (CTR == 1)
// 在加解密之前需要AES_init_ctx和初始化IV
// 加解密是相同的
// 每次加解密一个块，也就是16字节，buf长度为AES_BLOCKLEN
void AES_CTR_xcrypt_buffer(const uint8_t* sbox, struct AES_ctx* ctx, uint8_t* buf, size_t length);
#endif




// 定义将用到的数学操作
// xtime：x乘法
// multiply：用于将字段 GF(2^8) 中的数字相乘
# define xtime(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))
# define multiply(x, y)                               \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

/**************************************************************
  KeyExpansion：  密钥拓展 
  Input:
          RoundKey 初始密钥
  Output:
          Key 拓展后长度为Nb(Nr+1)的轮密钥
**************************************************************/
void KeyExpansion(const uint8_t* sbox, uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // 第一轮的轮密钥为初始密钥
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // 其余的轮密钥由先前的轮密钥得出
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // 偏移操作，向左移动一个单位
      // 例如：[a0,a1,a2,a3] -> [a1,a2,a3,a0]
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // S盒字节替换
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

/**************************************************************
  AddRoundKey:  为状态矩阵加上轮密钥，使用异或操作
  Input: 
         round 轮数（第几轮加密）
         state 状态矩阵
         RoundKey 轮密钥
  Output:
         state 加上轮密钥后的状态矩阵
**************************************************************/
__host__ __device__ void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

/***************************************************************** 加密过程 ************************************************************/

/**************************************************************
  SubBytes: 对状态矩阵进行S盒替换
  Input: 
         state 状态矩阵
  Output:
         state S盒替换后的状态矩阵
**************************************************************/
__host__ __device__ void SubBytes(state_t* state, const uint8_t *sbox)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = sbox[(*state)[j][i]];
    }
  }
}

/**************************************************************
  ShiftRows:  行移位
  Input: 
         state 状态矩阵
  Output:
         state 行移位后的状态矩阵
  Decription:
       ShiftRows() 函数将状态矩阵中的行向左移动
       每行以不同的偏移量移动，偏移量 = 行号，所以第一行实际上没有移动
**************************************************************/
__host__ __device__ void ShiftRows(state_t* state)
{
  uint8_t temp;
  // 第1行不用滚
  // 第2行向左滚1列
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // 第3行向左滚2列
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // 第4行向左滚3列
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

/**************************************************************
  MixColumns:  列混合
  Input: 
         state 状态矩阵
  Output:
         state 列混合后的状态矩阵
**************************************************************/
__host__ __device__ void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ; Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

/**************************************************************
  Cipher：  加密过程的主函数
  Input:
          state 初始状态矩阵
          RoundKey 经密钥拓展后的轮密钥
  Output:
          state 加密后的状态矩阵，即密文
**************************************************************/
__host__ __device__ void Cipher(const uint8_t *sbox, state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // 第一轮加密之前将初始密钥添加到状态矩阵
  AddRoundKey(0, state, RoundKey);
  // 进行Nr轮加密，前Nr-1轮的加密过程是相同的，最后一轮加密不需要进行列混合
  for (round = 1; ; ++round)
  {
    SubBytes(state, sbox);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // 最后一轮的轮密钥加
  AddRoundKey(Nr, state, RoundKey);
}

__global__ void Cipher_Kernel_ECB(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t AES_num_block)
{
  int x = threadIdx.x + (blockDim.x * blockIdx.x);
  if(x < AES_num_block)
    Cipher(sbox, (state_t*)buf + x, ctx->RoundKey);
}

__global__ void Cipher_Kernel_CTR(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t AES_num_block)
{
  size_t x = threadIdx.x + (blockDim.x * blockIdx.x);
  if(x < AES_num_block)
  {
    size_t i, remain;
    uint8_t buffer[AES_BLOCKLEN];
    memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
    // counter = Iv + x
    for(remain = x, i = (AES_BLOCKLEN - 1); remain > 0 && i >= 0; remain /= 256, i--){
        if((short)buffer[i] + (short)(remain % 256) > 255 && i > 0) // 处理进位
            buffer[i - 1]++;
        buffer[i] += remain % 256;
    }
    Cipher(sbox, (state_t*)buffer, ctx->RoundKey);
    
    for(i = 0; i < AES_BLOCKLEN; i++)
      buf[(x * AES_BLOCKLEN) + i] = (buf[(x * AES_BLOCKLEN) + i] ^ buffer[i]); 
  }
}

/***************************************************************** 解密过程 ************************************************************/
// ECB、CBC模式所需要的解密操作
// CTR不需要，因为对于CTR模式来说加解密过程是相同的
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/**************************************************************
  InvSubBytes: 对状态矩阵进行逆S盒替换
  Input: 
         state 状态矩阵
  Output:
         state 逆S盒替换后的状态矩阵
**************************************************************/
__host__ __device__ void InvSubBytes(state_t* state, const uint8_t *rsbox)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = rsbox[(*state)[j][i]];
    }
  }
}

/**************************************************************
  InvShiftRows:  逆行移位
  Input: 
         state 状态矩阵
  Output:
         state 逆行移位后的状态矩阵
  Decription:
         偏移量 = 行号
**************************************************************/
__host__ __device__ void InvShiftRows(state_t* state)
{
  uint8_t temp;
  // 第1行不用滚
  // 第2行向右滚1列
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // 第3行向右滚2列
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // 第4行向右滚3列
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}

/**************************************************************
  InvMixColumns:  逆列混合
  Input: 
         state 状态矩阵
  Output:
         state 逆列混合后的状态矩阵
**************************************************************/
__host__ __device__ void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
    (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
    (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
    (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
  }
}

/**************************************************************
  InvCipher：  解密过程的主函数
  Input:
          state 待解密的状态矩阵
          RoundKey 经密钥拓展后的轮密钥
  Output:
          state 解密后的状态矩阵，即明文
**************************************************************/
__host__ __device__ void InvCipher(const uint8_t *rsbox, state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // 第一轮解密之前将初始密钥添加到状态矩阵
  AddRoundKey(Nr, state, RoundKey);

  // 进行Nr轮解密，前Nr-1轮的解密过程是相同的，最后一轮解密不需要进行逆列混合
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state, rsbox);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}

__global__ void InvCipher_Kernel_ECB(const uint8_t* rsbox, const struct AES_ctx* ctx, uint8_t* buf, size_t AES_num_block)
{
  int x = threadIdx.x + blockDim.x * blockIdx.x;
  if(x < AES_num_block)
    InvCipher(rsbox, (state_t*)buf + x, ctx->RoundKey);
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)



/************************************************************** 不同模式的加解密接口 ************************************************************/
// 初始化部分
/**************************************************************
  AES_init_ctx: 初始化轮密钥
  Input: 
         key 初始密钥
  Output:
         ctx->RoundKey(ctx) 对key做密钥拓展后的轮密钥
**************************************************************/
 void AES_init_ctx(const uint8_t* sbox, struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(sbox, ctx->RoundKey, key);
}

// CBC和CTR模式需要初始化IV（ECB模式不需要初始化IV）
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
/**************************************************************
  AES_init_ctx_iv: 初始化轮密钥和初始向量IV
  Input: 
         key 初始密钥
         iv 初始向量
  Output:
         ctx 初始化后的轮密钥和初始向量IV
**************************************************************/
 void AES_init_ctx_iv(const uint8_t* sbox, struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(sbox, ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}

/**************************************************************
  AES_ctx_set_iv: 设置初始向量
**************************************************************/
 void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif


// ECB模式加解密
#if defined(ECB) && (ECB == 1)
void AES_ECB_encrypt_buffer(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  // 使用AES算法对buf进行加密
  size_t i;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    Cipher(sbox, (state_t*)buf, ctx->RoundKey);
    buf += AES_BLOCKLEN;
  }
}

void AES_ECB_decrypt_buffer(const uint8_t* rsbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  // 使用AES算法对buf进行解密
  size_t i;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    InvCipher(rsbox, (state_t*)buf, ctx->RoundKey);
    buf += AES_BLOCKLEN;
  }
}

void AES_ECB_encrypt_buffer_parallel(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
	cudaDeviceProp prop;	//cudaDeviceProp的一个对象
	cudaGetDeviceProperties(&prop, 0);	//第二参数为那个gpu

  uint8_t *d_buf, *d_sbox;
  struct AES_ctx* d_ctx;
  // allocate device memory
  cudaMalloc((void**)&d_buf, sizeof(uint8_t) * length);
  cudaMalloc((void**)&d_ctx, sizeof(struct AES_ctx));
  cudaMalloc((void**)&d_sbox, sizeof(uint8_t) * 256);
  // host send data: host => device
  cudaMemcpy(d_buf, buf, sizeof(uint8_t) * length, cudaMemcpyHostToDevice);
  cudaMemcpy(d_ctx, ctx, sizeof(struct AES_ctx), cudaMemcpyHostToDevice);
  cudaMemcpy(d_sbox, sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);
  // compute
  size_t AES_num_block = length / AES_BLOCKLEN;
  size_t threadPerBlock = min(AES_num_block, (size_t)prop.maxThreadsPerBlock);
  size_t blockNumber = (AES_num_block + threadPerBlock - 1) / threadPerBlock;
  // dim3 threadPerBlock(32, 32);
  // dim3 blockNumber((((AES_num_block + stride - 1) / stride) + 1024 - 1) / 1024, 1);
    // printf("threadPerBlock%ld\n", threadPerBlock);
  Cipher_Kernel_ECB<<<blockNumber, threadPerBlock>>> (d_sbox, d_ctx, d_buf, AES_num_block);
  // host receive data: device => host
  cudaMemcpy(buf, d_buf, sizeof(uint8_t) * length, cudaMemcpyDeviceToHost);
  // release device memory
  cudaFree(d_buf);
  cudaFree(d_ctx);
  cudaFree(d_sbox);
}

void AES_ECB_decrypt_buffer_parallel(const uint8_t* rsbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
	cudaDeviceProp prop;	//cudaDeviceProp的一个对象
	cudaGetDeviceProperties(&prop, 0);	//第二参数为那个gpu

  uint8_t *d_buf, *d_rsbox;
  struct AES_ctx* d_ctx;
  // allocate device memory
  cudaMalloc((void**)&d_buf, sizeof(uint8_t) * length);
  cudaMalloc((void**)&d_ctx, sizeof(struct AES_ctx));
  cudaMalloc((void**)&d_rsbox, sizeof(uint8_t) * 256);
  // host send data: host => device
  cudaMemcpy(d_buf, buf, sizeof(uint8_t) * length, cudaMemcpyHostToDevice);
  cudaMemcpy(d_ctx, ctx, sizeof(struct AES_ctx), cudaMemcpyHostToDevice);
  cudaMemcpy(d_rsbox, rsbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);
  // compute
  size_t AES_num_block = length / AES_BLOCKLEN;
  size_t threadPerBlock = min(AES_num_block, (size_t)prop.maxThreadsPerBlock);
  size_t blockNumber = (AES_num_block + threadPerBlock - 1) / threadPerBlock;
  InvCipher_Kernel_ECB<<<blockNumber, threadPerBlock>>> (d_rsbox, d_ctx, d_buf, AES_num_block);
  // host receive data: device => host
  cudaMemcpy(buf, d_buf, sizeof(uint8_t) * length, cudaMemcpyDeviceToHost);
  // release device memory
  cudaFree(d_buf);
  cudaFree(d_ctx);
  cudaFree(d_rsbox);
}
#endif // #if defined(ECB) && (ECB == 1)


// CBC模式加解密
#if defined(CBC) && (CBC == 1)
/**************************************************************
  XorWithIv:  将分组和初始向量Iv异或
  Input: 
         buf 分组
         Iv 初始向量
  Output:
         buf 异或后的分组
**************************************************************/
void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(const uint8_t* sbox, struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher(sbox, (state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  // 存储当前加密后的块作为下一个块加密的Iv
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(const uint8_t* rsbox, struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher(rsbox, (state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)

// CTR模式加解密
#if defined(CTR) && (CTR == 1)
// CTR模式加解密为对称操作，即加密和解密的过程相同，IV/nonce 都不应与相同的密钥重用 
void AES_CTR_xcrypt_buffer(const uint8_t* sbox, struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN)// 生成新的组
    {
      // 对计数器进行加密
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher(sbox, (state_t*)buffer,ctx->RoundKey);

      // 增加 Iv 并处理溢出
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
        if (ctx->Iv[bi] == 255)
        {
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]); // 将计数器加密结果与明文组进行异或 
  }
}

void AES_CTR_xcrypt_buffer_parallel(const uint8_t* sbox, struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
	cudaDeviceProp prop;	//cudaDeviceProp的一个对象
	cudaGetDeviceProperties(&prop, 0);	//第二参数为GPU的id，只有一个GPU，故id为0

  uint8_t *d_buf, *d_sbox;
  struct AES_ctx* d_ctx;
  // allocate device memory
  cudaMalloc((void**)&d_buf, sizeof(uint8_t) * length);
  cudaMalloc((void**)&d_ctx, sizeof(struct AES_ctx));
  cudaMalloc((void**)&d_sbox, sizeof(uint8_t) * 256);
  // host send data: host => device
  cudaMemcpy(d_buf, buf, sizeof(uint8_t) * length, cudaMemcpyHostToDevice);
  cudaMemcpy(d_ctx, ctx, sizeof(struct AES_ctx), cudaMemcpyHostToDevice);
  cudaMemcpy(d_sbox, sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);
  // compute
  size_t AES_num_block = length / AES_BLOCKLEN;
  size_t threadPerBlock = min(AES_num_block, (size_t)prop.maxThreadsPerBlock);
  size_t blockNumber = (AES_num_block + threadPerBlock - 1) / threadPerBlock;
  Cipher_Kernel_CTR<<<blockNumber, threadPerBlock>>> (d_sbox, d_ctx, d_buf, AES_num_block);
  // host receive data: device => host
  cudaMemcpy(buf, d_buf, sizeof(uint8_t) * length, cudaMemcpyDeviceToHost);
  // release device memory
  cudaFree(d_buf);
  cudaFree(d_ctx);
  cudaFree(d_sbox);
}

#endif // #if defined(CTR) && (CTR == 1)

#endif
