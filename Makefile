TARGET = exp

all: $(TARGET)

CFLAGS = ""
FRAMEWORKS = -framework IOKit -framework Foundation -framework CoreFoundation

$(TARGET): exp.m 
	clang $(CFLAGS) $(FRAMEWORKS) -pagezero_size 0x16000 $^ -o $@
clean:
	rm -f -- $(TARGET)
