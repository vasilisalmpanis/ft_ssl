NAME    =   ft_ssl
SRC     =   src/main.c
RM      =   rm -rf
CC      =   gcc
CFLAGS  =   -Wall -Wextra -Werror

OBJ     =   $(SRC:.c=.o)

all: ${NAME}

${NAME}: ${OBJ}
		${CC} ${CFLAGS} ${OBJ} -o ${NAME}

%.o: %.c
		${CC} ${CFLAGS} -c $< -o $@

clean:
		${RM} ${OBJ}

fclean: clean
		${RM} ${NAME}

re: fclean all

.PHONY: all clean fclean re
