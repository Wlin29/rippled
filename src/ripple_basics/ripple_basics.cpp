//------------------------------------------------------------------------------
/*
    Copyright (c) 2011-2013, OpenCoin, Inc.
*/
//==============================================================================

/** Add this to get the @ref ripple_basics module.

    @file ripple_basics.cpp
    @ingroup ripple_basics
*/

#include "BeastConfig.h"

#include "ripple_basics.h"

//------------------------------------------------------------------------------

// For Sustain Linux variants
//
// VFALCO TODO Rewrite Sustain to use beast::Process
#ifdef __linux__
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#endif
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/wait.h>
#endif

//------------------------------------------------------------------------------

// For json/
//
#ifdef JSON_USE_CPPTL
# include <cpptl/conststring.h>
#endif
#ifndef JSON_USE_SIMPLE_INTERNAL_ALLOCATOR
#include "json/json_batchallocator.h"
#endif

#define JSON_ASSERT_UNREACHABLE assert( false )
#define JSON_ASSERT( condition ) assert( condition );  // @todo <= change this into an exception throw
#define JSON_ASSERT_MESSAGE( condition, message ) if (!( condition )) throw std::runtime_error( message );

//------------------------------------------------------------------------------

// For random numbers
//
// VFALCO TODO Replace OpenSSL randomness with a dependency-free implementation
//         Perhaps Schneier's Fortuna or a variant. Abstract the collection of
//         entropy and provide OS-specific implementation. We can re-use the
//         BearShare source code for this.
//
//         Add Random number generation to beast
//
#include <openssl/rand.h> // Because of ripple_RandomNumbers.cpp

#ifdef BEAST_WIN32
# include <windows.h>  // for ripple_RandomNumbers.cpp
# include <wincrypt.h> // for ripple_RandomNumbers.cpp
# include <Winsock2.h> // for ripple_ByteOrder.cpp
// <Winsock2.h> defines 'max' and does other stupid things
# ifdef max
# undef max
# endif
#endif

//------------------------------------------------------------------------------

namespace ripple
{

#include "containers/RangeSet.cpp"
#include "containers/TaggedCache.cpp"

#include "json/json_reader.cpp"
#include "json/json_value.cpp"
#include "json/json_writer.cpp"

#include "log/Log.cpp"
#include "log/LogFile.cpp"
#include "log/LogJournal.cpp"
#include "log/LogPartition.cpp"
#include "log/LogSink.cpp"

#include "utility/ByteOrder.cpp"
#include "utility/CountedObject.cpp"
#include "utility/DiffieHellmanUtil.cpp"
#include "utility/IniFile.cpp"
#include "utility/StringUtilities.cpp"
#include "utility/Sustain.cpp"
#include "utility/ThreadName.cpp"
#include "utility/Time.cpp"
#include "utility/UptimeTimer.cpp"

#include "utility/RandomNumbers.cpp" // has Win32/Posix dependencies

#include "types/UInt256.cpp"

}
