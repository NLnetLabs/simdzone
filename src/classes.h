#ifndef CLASSES_H
#define CLASSES_H

#define CONTIGUOUS (0x00u)   // <*********> -- contiguous
#define BLANK (0x01u)        // " "  : 0x20 |- blank
                             // "\t" : 0x09 |
                             // "\r" : 0x0d |
#define BACKSLASH (0x02u)    // "\\" : 0x5c -- escapes character
#define NEWLINE (0x03u)      // "\n" : 0x0a -- ends record/comment
#define SEMICOLON (0x04u)    // ";"  : 0x3b -- starts comments
#define PARENTHESES (0x05u)  // "("  : 0x28 -- starts/ends grouped
                             // ")"  : 0x29 |
#define QUOTE (0x06u)        // "\"" : 0x22 -- starts/ends quoted

#define SPECIAL (BACKSLASH)

#endif // CLASSES_H
