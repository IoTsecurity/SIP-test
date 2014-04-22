/*
 * test.h
 *
 *  Created on: 2014年4月22日
 *      Author: root
 */

#ifndef TEST_H_
#define TEST_H_


int changeTo(enum DeviceType from_type,enum DeviceType to_type);
int codeTOChar(char *data,int lenth);
int decodeFromChar(char *data,int lenth);
int printfx(unsigned char *p, int len);

#endif /* TEST_H_ */
