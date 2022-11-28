CC = cl
CC_FLAGS=/c

.SUFFIXES: .obj .c

.c.obj:
	$(CC) $(CC_FLAGS) $< 

all: cwe22_path_traversal.obj \
	cwe78_os_command_injection.obj \
	cwe120_classic_buffer_overflow.obj \
	cwe121_stack_buffer_overflow.obj \
	cwe131_incorrect_buffer_size.obj \
	cwe134_uncontrolled_format_string.obj 

clean:
	-rm -f *.obj

