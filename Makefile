# makefile Date class

main: main.o IDEA.o
	g++ -o main -std=c++11  main.o IDEA.o
main.o: main.cpp
	g++ -c  -std=c++11  main.cpp
DAte.o: IDEA.h IDEA.cpp
	g++ -c  -std=c++11   IDEA.h
	g++ -c  -std=c++11   IDEA.cpp
clean:
	-rm *.h.gch
	-rm *.o
