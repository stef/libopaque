JAVAINCLUDES?=/usr/lib/jvm/java-11-openjdk/include/
JAVA_SOURCES = $(wildcard ctrlc/*.java)

all: opaque.jar libopaquejni.so

opaque.jar: test.java $(JAVA_SOURCES) jni.c
	javac -d build test.java $(JAVA_SOURCES)
	jar -cvfe opaque.jar Main build

libopaquejni.so: jni.c
	gcc jni.c -shared -fPIC -o libopaquejni.so -I$(JAVAINCLUDES) -I$(JAVAINCLUDES)/linux -lopaque

test: opaque.jar libopaquejni.so
	java -enableassertions -Djava.library.path=. -classpath build:opaque.jar Main

clean:
	rm -rf build
	rm -f opaque.jar
	rm -f libopaquejni.so
