all: opaque.jar libopaquejni.so

opaque.jar: test.java opaque.java jni.c
	javac -d build test.java opaque.java
	jar -cvfe opaque.jar Main build

libopaquejni.so: jni.c
	gcc jni.c -shared -fPIC -o libopaquejni.so -I/usr/lib/jvm/java-11-openjdk/include/ -I/usr/lib/jvm/java-11-openjdk/include/linux -lopaque

test: opaque.jar libopaquejni.so
	java -enableassertions -Djava.library.path=. -classpath build:opaque.jar Main

clean:
	rm -rf build
	rm -f opaque.jar
	rm -f libopaquejni.so
