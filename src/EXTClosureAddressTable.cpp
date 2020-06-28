#include <EXTClosureAddressTable.h>

#include <cstring>

namespace extemp {
namespace ClosureAddressTable {
EXPORT closure_address_table * get_address_table(const char *name, closure_address_table *table) {
    while (table) {
        if (strcmp(table->name, name))
            return table;
        table = table->next;
    }
    printf("Unable to locate %s in closure environment a\n", name);
    return 0;
}

EXPORT uint32_t get_address_offset(uint64_t id, closure_address_table* table)
{
    while(table)
    {
        // printf("%p name: %s\ntablename: %s\n\n", name, name, table->name);
        if(table->id == id) {
            // printf("in %s returning offset %d from %s\n", table->name, table->offset, name);
            return table->offset;
        }
        table = table->next;
    }
    printf("Unable to locate %" PRIu64 " in closure environment b\n", id);
    return 0;
}

EXPORT bool check_address_exists(uint64_t id, closure_address_table* table)
{
    do {
        if (table->id == id) {
            return true;
        }
        table = table->next;
    } while (table);
    return false;
}

EXPORT bool check_address_type(uint64_t id, closure_address_table* table, const char* type)
{
    while(table)
    {
        if(table->id == id) {
            if((strcmp(table->type, type)!=0) && (strcmp("{i8*, i8*, void (i8*, i8*)*}**", type) != 0)) {
                printf("Runtime Type Error: bad type %s for %s. Should be %s\n", type, table->name, table->type);
                return 0;
            }
            else {
                return 1;
            }
        }
        table = table->next;
    }
    printf("Unable to locate id in closure environment type: %s d\n",type);
    return 0;
}

    
} // namespace ClosureAddressTable
} // namespace extemp
