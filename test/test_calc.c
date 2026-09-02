/* Recursive-descent calculator with a small variable table.
   A bigger target than test_target.c: several call levels, mutual recursion
   in the parser, and a comparison function reached only through qsort. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VARS 16
#define NAME_LEN 16

struct var {
    char name[NAME_LEN];
    double value;
};

static struct var vars[MAX_VARS];
static int var_count;
static const char *cursor;
static int had_error;

static void fail(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    had_error = 1;
}

static void skip_spaces(void)
{
    while (*cursor == ' ' || *cursor == '\t')
        cursor++;
}

static int peek(void)
{
    skip_spaces();
    return (unsigned char)*cursor;
}

static int match(char c)
{
    if (peek() != c)
        return 0;
    cursor++;
    return 1;
}

static struct var *var_find(const char *name)
{
    for (int i = 0; i < var_count; i++)
        if (strcmp(vars[i].name, name) == 0)
            return &vars[i];
    return NULL;
}

static void var_set(const char *name, double value)
{
    struct var *v = var_find(name);

    if (v == NULL) {
        if (var_count == MAX_VARS) {
            fail("too many variables");
            return;
        }
        v = &vars[var_count++];
        snprintf(v->name, NAME_LEN, "%s", name);
    }
    v->value = value;
}

static double var_get(const char *name)
{
    struct var *v = var_find(name);

    if (v == NULL) {
        fail("undefined variable");
        return 0.0;
    }
    return v->value;
}

static void read_name(char *out)
{
    int n = 0;

    skip_spaces();
    while (isalnum((unsigned char)*cursor) || *cursor == '_') {
        if (n < NAME_LEN - 1)
            out[n++] = *cursor;
        cursor++;
    }
    out[n] = '\0';
}

static double read_number(void)
{
    char *end;
    double value;

    skip_spaces();
    value = strtod(cursor, &end);
    if (end == cursor)
        fail("bad number");
    cursor = end;
    return value;
}

static double parse_expr(void);

static double parse_factor(void)
{
    char name[NAME_LEN];

    if (match('(')) {
        double value = parse_expr();

        if (!match(')'))
            fail("missing )");
        return value;
    }
    if (match('-'))
        return -parse_factor();
    if (isdigit(peek()))
        return read_number();
    if (isalpha(peek())) {
        read_name(name);
        return var_get(name);
    }
    fail("unexpected character");
    return 0.0;
}

static double parse_term(void)
{
    double value = parse_factor();

    for (;;) {
        if (match('*')) {
            value *= parse_factor();
        } else if (match('/')) {
            double divisor = parse_factor();

            if (divisor == 0.0) {
                fail("division by zero");
                return 0.0;
            }
            value /= divisor;
        } else {
            return value;
        }
    }
}

static double parse_expr(void)
{
    double value = parse_term();

    for (;;) {
        if (match('+'))
            value += parse_term();
        else if (match('-'))
            value -= parse_term();
        else
            return value;
    }
}

static int compare_vars(const void *a, const void *b)
{
    const struct var *left = a;
    const struct var *right = b;

    return strcmp(left->name, right->name);
}

static void dump_vars(void)
{
    qsort(vars, var_count, sizeof vars[0], compare_vars);
    puts("variables:");
    for (int i = 0; i < var_count; i++)
        printf("  %-8s = %g\n", vars[i].name, vars[i].value);
}

static void run_line(const char *line)
{
    char name[NAME_LEN];

    cursor = line;
    read_name(name);
    if (name[0] != '\0' && match('=')) {
        var_set(name, parse_expr());
        printf("%-16s -> %s = %g\n", line, name, var_get(name));
        return;
    }
    cursor = line;
    printf("%-16s = %g\n", line, parse_expr());
}

static void banner(const char *title)
{
    puts(title);
    puts("--------------------");
}

int main(void)
{
    banner("calc");
    run_line("x = 2 + 3 * 4");
    run_line("y = (x - 2) / 3");
    run_line("x * y + 1");
    run_line("-x + 100");
    dump_vars();
    return had_error;
}
