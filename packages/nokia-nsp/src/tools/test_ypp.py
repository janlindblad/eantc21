import difflib
import inspect
import os
import pytest
import tempfile
from ypp import ypp

def run(variables, source_data, expected_data, fr=[], to=[]):
    print("\n\n%s" % inspect.stack()[1][3])

    with tempfile.NamedTemporaryFile(dir="/tmp", suffix=".tmp", mode="w", delete=False) \
        as source_file:
        source_file.write(source_data)

    args = [("--var=%s" % v) for v in variables] + \
           [("--from=%s" % f) for f in fr] + \
           [("--to=%s" % t) for t in to] + \
           ["--verbose", source_file.name]
    print(args)
    ypp(args)

    with open(source_file.name) as destination_file:
        destination_data = destination_file.read()
    for line in difflib.unified_diff(expected_data.split("\n"),
                                     destination_data.split("\n")):
        print(line)
    assert expected_data == destination_data
    os.remove(source_file.name)

def test_ypp_if_numeric_if():
    run(["VAR=5"],
        """
        #if (VAR == 5)
            YES
        #elif (VAR == 5)
            NO
        #else
            NO
        #endif
        """,
        """
        #if (VAR == 5)
            YES
        #elif (VAR == 5)
        #else
        #endif
        """
    )

def test_ypp_if_numeric_elif():
    run(["VAR=5"],
        """
        #if (VAR == 4)
            NO
        #elif (VAR == 5)
            YES
        #else
            NO
        #endif
        """,
        """
        #if (VAR == 4)
        #elif (VAR == 5)
            YES
        #else
        #endif
        """
    )

def test_ypp_if_numeric_else():
    run(["VAR=5"],
        """
        #if (VAR == 4)
            NO
        #elif (VAR == 4)
            NO
        #else
            YES
        #endif
        """,
        """
        #if (VAR == 4)
        #elif (VAR == 4)
        #else
            YES
        #endif
        """
    )

def test_ypp_if_numeric_if_nested_if():
    run(["VAR=5"],
        """
        #if (VAR == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #elif (VAR == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #endif
        """,
        """
        #if (VAR == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #elif (VAR == 5)
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #else
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #endif
        """
    )

def test_ypp_if_numeric_if_nested_elif():
    run(["VAR=5"],
        """
        #if (VAR == 4)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #elif (VAR == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #endif
        """,
        """
        #if (VAR == 4)
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #elif (VAR == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #else
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #endif
        """
    )

def test_ypp_if_numeric_if_nested_else():
    run(["VAR=5"],
        """
        #if (VAR == 4)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #elif (VAR == 4)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #endif
        """,
        """
        #if (VAR == 4)
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #elif (VAR == 4)
            #if (VAR == 5)
            #elif (VAR == 5)
            #else
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #endif
        """
    )

def test_ypp_if_numeric_if_nested_defer():
    run(["VAR=5"],
        """
        #if (UNDEF == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #elif (UNDEF == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
                NO
            #else
                NO
            #endif
        #endif
        """,
        """
        #if (UNDEF == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #elif (UNDEF == 5)
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #else
            #if (VAR == 5)
                YES
            #elif (VAR == 5)
            #else
            #endif
        #endif
        """
    )

def test_ypp_if_string():
    run(["VAR=FIVE"],
        """
        #if (VAR == "FIVE")
            YES
        #endif
        """,
        """
        #if (VAR == "FIVE")
            YES
        #endif
        """
    )

def test_ypp_var_numeric():
    run(["VAR=5"],
        """
        #var(VAR)
        """,
        """
        5
        """
    )

def test_ypp_var_string():
    run(["VAR=FIVE"],
        """
        #var(VAR)
        """,
        """
        FIVE
        """
    )

def test_ypp_line_numeric():
    run(["VAR=5"],
        """
        #line(VAR)
        """,
        """
5
        """
    )

def test_ypp_line_string():
    run(["VAR=FIVE"],
        """
        #line(VAR)
        """,
        """
FIVE
        """
    )

def test_ypp_define_numeric():
    run([],
        """
        #define VAR (5)
        #var(VAR)
        """,
        """
        #define VAR (5)
        5
        """
    )

def test_ypp_define_string():
    run([],
        """
        #define VAR1 (FIVE)
        #define VAR2 ("FIVE")
        #var(VAR1)
        #var(VAR2)
        """,
        """
        #define VAR1 (FIVE)
        #define VAR2 ("FIVE")
        FIVE
        "FIVE"
        """
    )

def test_ypp_replace_if():
    run(["VAR=5"],
        """
        #if (VAR == 5)
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            //REMOVEIT
            //REPLACEIT
        #else
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            //REMOVEIT
            //REPLACEIT
        #endif
        """,
        """
        #if (VAR == 5)
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            IT
            CHANGEIT
        #else
        #endif
        """
    )

def test_ypp_replace_else():
    run(["VAR=5"],
        """
        #if (VAR == 4)
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            //REMOVEIT
            //REPLACEIT
        #else
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            //REMOVEIT
            //REPLACEIT
        #endif
        """,
        """
        #if (VAR == 4)
        #else
            #replace (//REMOVE) ()
            #replace (//REPLACE) (CHANGE)
            IT
            CHANGEIT
        #endif
        """
    )

def test_ypp_replace_nested():
    run(["VAR=5"],
        """
        #if (VAR == 5)
            #if (VAR == 5)
                #replace (//REMOVE) ()
                #replace (//REPLACE) (CHANGE)
                //REMOVEIT
                //REPLACEIT
            #else
                #replace (//REMOVE) ()
                #replace (//REPLACE) (CHANGE)
                //REMOVEIT
                //REPLACEIT
            #endif
            //REMOVEIT
            //REPLACEIT
        #else
            //REMOVEIT
            //REPLACEIT
        #endif
        """,
        """
        #if (VAR == 5)
            #if (VAR == 5)
                #replace (//REMOVE) ()
                #replace (//REPLACE) (CHANGE)
                IT
                CHANGEIT
            #else
            #endif
            //REMOVEIT
            //REPLACEIT
        #else
        #endif
        """
    )

def test_ypp_if_version():
    run(["VAR=1.2.3"],
        """
        #if (version(VAR) == version("1.2.3"))
            YES
        #endif
        #if (version(VAR) > version("1.2.2"))
            YES
        #endif
        #if (version(VAR) > version("1.2.4"))
            NO
        #endif
        #if (version(VAR) > version("1.2.22"))
            NO
        #endif
        """,
        """
        #if (version(VAR) == version("1.2.3"))
            YES
        #endif
        #if (version(VAR) > version("1.2.2"))
            YES
        #endif
        #if (version(VAR) > version("1.2.4"))
        #endif
        #if (version(VAR) > version("1.2.22"))
        #endif
        """
    )

def test_ypp_syntax_error():
    with pytest.raises(ValueError):
        run([],
            """
            #if a > b
            """,
            """
            """
        )

def test_ypp_from_to():
    run([],
        """
        FROM
        TO
        FROM
        """,
        """
        TO
        TO
        TO
        """,
        fr=["FROM"],
        to=["TO"]
    )

def test_ypp_from_none():
    with pytest.raises(ValueError):
        run([],
            """
            """,
            """
            """,
            fr=["FROM"],
            to=[]
        )
