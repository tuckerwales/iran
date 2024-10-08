#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "crc.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include <string.h>

// AES key used for encryption
const unsigned char AES_KEY_837[] = {0x18, 0x84, 0x58, 0xA6, 0xD1, 0x50, 0x34, 0xDF, 0xE3, 0x86, 0xF2, 0x3B, 0x61, 0xD4, 0x37, 0x74};

// Function to print a buffer in hexadecimal format
void hexdump(unsigned char *data, int length)
{
    for (int i = 0; i < length; i++)
    {
        if (i % 16 == 0 && i != 0)
            printf("\n");
        printf("%2.2X ", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    printf("DFU unsigned execute by geohot\n");
    printf("Based off the dev team's Pwnage 2.0 exploit\n");

    if (argc < 2)
    {
        printf("Usage: %s <filename>\n", argv[0]);
        return -1;
    }

    // Open the required files
    FILE *cert_file = fopen("cert", "rb");
    FILE *input_file = fopen(argv[1], "rb");

    if (!cert_file || !input_file)
    {
        printf("File not found\n");
        return -1;
    }

    // Get the length of the certificate file
    fseek(cert_file, 0, SEEK_END);
    int cert_length = ftell(cert_file);
    fseek(cert_file, 0, SEEK_SET);

    // Get the length of the input file
    fseek(input_file, 0, SEEK_END);
    int input_length = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Allocate buffer memory
    unsigned char *buffer = (unsigned char *)malloc(0x800 + input_length + cert_length + 0x10);
    memset(buffer, 0, 0x800);

    // Read files into buffer
    fread(&buffer[0x800], 1, input_length, input_file);
    fread(&buffer[0x800 + input_length], 1, cert_length, cert_file);

    fclose(input_file);
    fclose(cert_file);

    printf("Files read: %X %X\n", input_length, cert_length);

    // Generate header
    strcpy((char *)buffer, "89001.0");
    buffer[7] = 0x04;
    buffer[0x3E] = 0x04;
    memcpy(&buffer[0xC], &input_length, 0x4); // Data size
    memcpy(&buffer[0x10], &input_length, 0x4); // Signature offset
    int cert_offset = input_length + 0x80;
    memcpy(&buffer[0x14], &cert_offset, 0x4); // Certificate offset
    int cert_length_offset = 0xC5E;
    memcpy(&buffer[0x18], &cert_length_offset, 0x4); // Certificate length

    printf("Header generated\n");

    // Hash the header
    unsigned char sha1_output[SHA_DIGEST_LENGTH];
    SHA1(buffer, 0x40, sha1_output);

    // Encrypt the SHA1 hash using AES
    AES_KEY aes_key;
    AES_set_encrypt_key(AES_KEY_837, 128, &aes_key);
    unsigned char iv[0x10] = {0};
    AES_cbc_encrypt(sha1_output, sha1_output, 0x10, &aes_key, iv, AES_ENCRYPT);
    memcpy(&buffer[0x40], sha1_output, 0x10);

    // Append DFU footer
    const char dfu_footer[] = {0xff, 0xff, 0xff, 0xff, 0xac, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10};
    memcpy(&buffer[0x800 + input_length + cert_length], dfu_footer, sizeof(dfu_footer));

    unsigned int crc = 0xFFFFFFFF;
    crc = update_crc(crc, buffer, 0x800 + input_length + cert_length + sizeof(dfu_footer));

    // Append CRC to the end of the buffer
    for (int i = 0; i < 4; i++)
    {
        buffer[0x800 + input_length + cert_length + sizeof(dfu_footer) + i] = crc & 0xFF;
        crc >>= 8;
    }

    // Initialize libusb
    libusb_context *ctx = NULL;
    struct libusb_device_handle *device_handle = NULL;
    int dfu_mode = 0;

    if (libusb_init(&ctx) < 0)
    {
        printf("Failed to initialize libusb\n");
        return -1;
    }

    printf("USB ready\n");

    // Find the device on the USB bus
    libusb_device **devices;
    ssize_t count = libusb_get_device_list(ctx, &devices);
    if (count < 0)
    {
        printf("Failed to get device list\n");
        libusb_exit(ctx);
        return -1;
    }

    for (ssize_t i = 0; i < count; i++)
    {
        libusb_device *dev = devices[i];
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) < 0)
            continue;

        printf(" %4.4X %4.4X\n", desc.idVendor, desc.idProduct);
        if (desc.idVendor == 0x5ac && desc.idProduct == 0x1222) // DFU Mode
        {
            printf("Found DFU device\n");
            if (libusb_open(dev, &device_handle) == 0)
            {
                dfu_mode = 2;
                break;
            }
        }
    }

    libusb_free_device_list(devices, 1);

    if (!device_handle)
    {
        printf("No device found\n");
        libusb_exit(ctx);
        return -1;
    }

    int packet_index = 0;
    int data_offset = 0;
    int total_bytes_to_send = 0x800 + input_length + cert_length + 0x10;
    printf("Sending 0x%x bytes\n", total_bytes_to_send);

    // Send data in chunks over USB
    while (data_offset < total_bytes_to_send + 0x800)
    {
        int bytes_left = total_bytes_to_send - data_offset;
        int chunk_size = (bytes_left > 0x800) ? 0x800 : bytes_left;

        int actual_length;
        int res = libusb_control_transfer(device_handle, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 1, packet_index, 0, &buffer[data_offset], chunk_size, 1000);
        if (res == chunk_size)
            printf(".");
        else
            printf("x");

        if (chunk_size == 0)
            printf("\n");

        int response_attempts = 0;
        while (libusb_control_transfer(device_handle, LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 3, 0, 0, (unsigned char *)buffer, 6, 1000) == 6 && response_attempts < 5)
        {
            response_attempts++;
            if (chunk_size == 0)
                hexdump(buffer, 6);
            if (buffer[4] == 5)
                break;
        }

        data_offset += 0x800;
        packet_index++;
    }

    // Close the USB device
    libusb_close(device_handle);
    libusb_exit(ctx);

    return 0;
}
