#include <stdio.h>
#include <stdlib.h> 
#include <sys/time.h>

#define TAILQ_ENTRY(type)                                            \
struct {                                                             \
    struct type *tqe_next;  /* next element */                       \
    struct type **tqe_prev;/* addr of previous next element*/        \
}   

#define    TAILQ_HEAD(name, type)                        \
struct name {                                \
    struct type *tqh_first;    /* first element */            \
    struct type **tqh_last;    /* addr of last next element */        \
}

#define    TAILQ_FIRST(head)    ((head)->tqh_first)
#define    TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#define    TAILQ_PREV(elm, headname, field)                \
    (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
    
#define    TAILQ_LAST(head, headname)                    \
    (*(((struct headname *)((head)->tqh_last))->tqh_last))
    
    
#define    TAILQ_INIT(head) do {                        \
    TAILQ_FIRST((head)) = NULL;                    \
    (head)->tqh_last = &TAILQ_FIRST((head));            \
} while (0)

#define TAILQ_INSERT_TAIL(head, elm, field) do {            \
    TAILQ_NEXT((elm), field) = NULL;                \
    (elm)->field.tqe_prev = (head)->tqh_last;            \
    *(head)->tqh_last = (elm);                    \
    (head)->tqh_last = &TAILQ_NEXT((elm), field);            \
} while (0)

#define    TAILQ_INSERT_BEFORE(listelm, elm, field) do {            \
    (elm)->field.tqe_prev = (listelm)->field.tqe_prev;        \
    TAILQ_NEXT((elm), field) = (listelm);                \
    *(listelm)->field.tqe_prev = (elm);                \
    (listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);        \
} while (0)

#define    TAILQ_FOREACH(var, head, field)                    \
    for ((var) = TAILQ_FIRST((head));                \
        (var);                            \
        (var) = TAILQ_NEXT((var), field))

#define    TAILQ_FOREACH_REVERSE(var, head, headname, field)        \
    for ((var) = TAILQ_LAST((head), headname);            \
        (var);                            \
        (var) = TAILQ_PREV((var), headname, field))
        
struct QUEUE_ITEM{  
    int value;  
    TAILQ_ENTRY(QUEUE_ITEM) entries;  
};  
TAILQ_HEAD(headname,QUEUE_ITEM) queue_head;  

#define ITEM_NUM 5000000
#define TRAVERSAL 20

int main(int argc,char **argv){  
    struct QUEUE_ITEM *item;   
    long long totaltime = 0;
    struct timeval start,end;
    long long metric[TRAVERSAL];
    int i = 0;
    
    TAILQ_INIT(&queue_head);  
    for(i=1;i<ITEM_NUM;i+=1){  
        item=malloc(sizeof(struct QUEUE_ITEM));  
        item->value=i;  
        TAILQ_INSERT_TAIL(&queue_head, item, entries);  
    }  
    
    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        TAILQ_FOREACH(item, &queue_head, entries)
        {
            item->value++;
        }   
        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("TAILQ traversal time is %lld us\n", totaltime/TRAVERSAL);

    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        TAILQ_FOREACH_REVERSE(item, &queue_head, headname,entries)
        {
            item->value++;
        }   
        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
    
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }
    
    printf("TAILQ reverse traversal time is %lld us\n", totaltime/TRAVERSAL);
    return 0; 
}  