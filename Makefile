TARGET1=aes-test
SRCS1=aes_test.cpp
OBJS1=$(SRCS1:.cpp=.o)
LIBS1=

TARGET2=aes-test-x86
SRCS2=aes_test_x86.cpp
OBJS2=$(SRCS2:.cpp=.o)
LIBS2=

CXXFLAGS=-std=c++20 -Wall -O2 -MD -maes -mssse3

DEPS=$(SRCS1:.cpp=.d) $(SRCS2:.cpp=.d)

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1)
	$(LINK.cpp) -o $@ $(OBJS1) $(LIBS1)

$(TARGET2): $(OBJS2)
	$(LINK.cpp) -o $@ $(OBJS2) $(LIBS2)

clean:
	$(RM) $(TARGET1) $(OBJS1)
	$(RM) $(TARGET2) $(OBJS2)
	$(RM) $(DEPS)

check-cpp: $(TARGET1)
	./$(TARGET1)

check-x86: $(TARGET2)
	./$(TARGET2)

check: check-cpp check-x86
test: check
run: check

sinclude $(DEPS)
