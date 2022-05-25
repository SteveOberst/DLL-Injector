#ifndef STRINGSEARCH_H
#define STRINGSEARCH_H

#include <string>
#include <locale>
#include <iostream>
#include <algorithm>

template<typename charT>
struct equal_ignore_case {
    equal_ignore_case( const std::locale& loc ) : loc_(loc) {}
    bool operator()(char ch1, char ch2) {
        return std::toupper(ch1, loc_) == std::toupper(ch2, loc_);
    }
private:
    const std::locale& loc_;
};

class StringSearch
{
public:
    StringSearch(){}

    ///
    /// \brief ci_find_substr finds the index of a substring in a case insensitive context
    /// \param str1 string to look through
    /// \param str2 string to search for
    /// \param loc locale
    /// \return index of found substring or -1 if none could be found
    ///
    template<typename T>
    int ci_find_substr( const T& str1, const T& str2, const std::locale& loc = std::locale())
    {
        typename T::const_iterator it = std::search( str1.begin(), str1.end(),
            str2.begin(), str2.end(), equal_ignore_case<typename T::value_type>(loc));
        if ( it != str1.end() ) return it - str1.begin();
        else return -1; // not found
    }
};

#endif // STRINGSEARCH_H
