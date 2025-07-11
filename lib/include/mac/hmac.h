#ifndef HMAC_H
#define HMAC_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */


void initHmac256_key(const uint32_t* key, const size_t keySize);
void startHmac256(const size_t macSize);
void updateHmac256(const size_t macSize, const uint32_t* text, const size_t textSize);
void finishHmac256(uint32_t* mac, const size_t macSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HMAC_H */
