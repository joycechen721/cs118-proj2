CXX=g++
CXXFLAGS=-I. -lcrypto -Wno-deprecated-declarations
USERID=123456789

HELPER_SRCS=$(wildcard helpers/*.cpp)
DEPS=$(HELPER_SRCS:.cpp=.d)

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

all: server client

security.o: security.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

server: server.o security.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS)

client: client.o security.o $(HELPER_SRCS:.cpp=.o)
	$(CXX) -o $@ $^ $(CXXFLAGS)

clean:
	rm -rf *.o helpers/*.o server client *.tar.gz

dist: tarball

tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz --exclude=./.vagrant . && mv /tmp/$(USERID).tar.gz .

.PHONY: clean dist tarball
