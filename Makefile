CC = g++

TARGET = jit

CFLAGS = -Wshadow -Winit-self -Wredundant-decls -Wcast-align -Wundef -Wfloat-equal -Winline -Wunreachable-code -Wmissing-declarations \
         -Wmissing-include-dirs -Wswitch-enum -Wswitch-default -Weffc++ -Wmain -Wextra -Wall -g -pipe -fexceptions -Wcast-qual	      \
         -Wconversion -Wctor-dtor-privacy -Wempty-body -Wformat-security -Wformat=2 -Wignored-qualifiers -Wlogical-op                 \
         -Wmissing-field-initializers -Wnon-virtual-dtor -Woverloaded-virtual -Wpointer-arith -Wsign-promo -Wstack-usage=8192         \
         -Wstrict-aliasing -Wstrict-null-sentinel -Wtype-limits -Wwrite-strings -D_DEBUG -D_EJUDGE_CLIENT_SIDE				     	  \

PREF_JIT_SRC = ./src/
PREF_OBJ = ./obj/

JIT_SRC = $(wildcard $(PREF_JIT_SRC)*.cpp)
JIT_OBJ = $(patsubst $(PREF_JIT_SRC)%.cpp,  $(PREF_OBJ)%.o, $(JIT_SRC))

OBJ = $(JIT_OBJ) main.o

all : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

$(PREF_OBJ)%.o : $(PREF_JIT_SRC)%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

$(PREF_OBJ)main.o : main.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean :
	rm $(TARGET) $(PREF_OBJ)*.o
