CXX=g++
CXXFLAGS=-I. -lcrypto -Wno-deprecated-declarations
USERID=123456789

HELPER_SRCS=$(wildcard helpers/*.cpp)
DEPS=$(HELPER_SRCS:.cpp=.d)

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $(CXXFLAGS)

all: server client
server: server.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS)

client: client.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS)

clean:
	rm -rf *.o helpers/*.o server client *.tar.gz

dist: tarball
tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz --exclude=./.vagrant . && mv /tmp/$(USERID).tar.gz .

# security:
# 	gcc ${CFLAGS} -o server server.cpp security.cpp
# 	gcc ${CFLAGS} -o client client.cpp security.cpp