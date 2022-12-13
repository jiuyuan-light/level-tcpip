
# 设置该变量后, 可以追加到文件
output_file='.gdbinit'

#  $1:funcname, $2:struct type, $3 Node list_head in the struct
function mk_print_list_head_macro () {
    # echo "func: \"$1\""
    # echo "struct type: \"$2\""
    # echo "Node list_head in the struct: \"$3\""
echo "

define $1
    set \$addr_lhead=\$arg0
    set \$offset = (int)&(($2*)0)->$3
    set \$pnode = ($2*)((char*)(((struct list_head *)\$addr_lhead)->next) - \$offset)
    p \"print some struct?\"
    while (&(\$pnode->$3) != \$addr_lhead)
        # 需要修订的区域 START, \$pnode是指向struct的指针
        p *\$pnode
        # 需要修订的区域 END
        set \$pnode = ($2*)((char*)\$pnode->$3.next - \$offset)
    end
end" | tee -a ${output_file}
}


# example
# mk_print_list_head_macro print_routes "struct rtentry" list
# mk_print_list_head_macro print_timers "struct timer" list