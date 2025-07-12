#ifndef HMAC_H
#define HMAC_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

void startHmac256(const uint32_t* key, const size_t keySize, const size_t macSize);
void updateHmac256(const size_t macSize, const uint32_t* text, const size_t textSize);
void finishHmac256(uint32_t* mac, const size_t macSize);

void startHmac512(const uint64_t* key, const size_t keySize, const size_t macSize);
void updateHmac512(const size_t macSize, const uint64_t* text, const size_t textSize);
void finishHmac512(uint64_t* mac, const size_t macSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HMAC_H */
