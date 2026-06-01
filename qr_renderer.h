#ifndef QR_RENDERER_H
#define QR_RENDERER_H

#include "qrcode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QR_MAX_BUFFER_SIZE 137

int8_t qr_init(const char *text, QRCode *qrcode, uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
