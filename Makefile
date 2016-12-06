PROG= ipscan
SRCS= ipscan.c utils.c

CFLAGS+= -O3 -Wall -Werror -std=c99

.include<bsd.prog.mk>
