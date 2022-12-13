#ifndef _LIST_H
#define _LIST_H

#include <stddef.h>

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

#define LIST_HEAD(name) struct list_head name = {&(name), &(name)}

static inline void list_init(struct list_head *head) {
  head->prev = head->next = head;
}

static inline void list_add(struct list_head *new, struct list_head *head) {
  head->next->prev = new;
  new->next = head->next;
  new->prev = head;
  head->next = new;
}

static inline void list_add_tail(struct list_head *new,
                                 struct list_head *head) {
  head->prev->next = new;
  new->prev = head->prev;
  new->next = head;
  head->prev = new;
}

static inline void list_del(struct list_head *elem) {
  struct list_head *prev = elem->prev;
  struct list_head *next = elem->next;

  prev->next = next;
  next->prev = prev;
}

#define list_entry(ptr, type, member)                                          \
  ((type *)((char *)(ptr)-offsetof(type, member)))

#define list_first_entry(ptr, type, member)                                    \
  list_entry((ptr)->next, type, member)

#define list_for_each(pos, head)                                               \
  for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, p, head)                                       \
  for (pos = (head)->next, p = pos->next; pos != (head); pos = p, p = pos->next)

static inline int list_empty(struct list_head *head) {
  return head->next == head;
}

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)                                 \
  for (pos = list_entry((head)->next, typeof(*pos), member);                   \
       &pos->member != (head);                                                 \
       pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against
 * removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)                         \
  for (pos = list_entry((head)->next, typeof(*pos), member),                   \
      n = list_entry(pos->member.next, typeof(*pos), member);                  \
       &pos->member != (head);                                                 \
       pos = n, n = list_entry(n->member.next, typeof(*n), member))

/* TAILQ */
#define TAILQ_HEAD(name, type)                                                 \
  struct name {                                                                \
    struct type *tqh_first; /* first element */                                \
    struct type **tqh_last; /* addr of last next element */                    \
  }

#define TAILQ_ENTRY(type)                                                      \
  struct {                                                                     \
    struct type *tqe_next;  /* next element */                                 \
    struct type **tqe_prev; /* addr of previous next element*/                 \
  }

#define TAILQ_FIRST(head) ((head)->tqh_first)
#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#define TAILQ_PREV(elm, headname, field)                                       \
  (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define TAILQ_LAST(head, headname)                                             \
  (*(((struct headname *)((head)->tqh_last))->tqh_last))

#define TAILQ_INIT(head)                                                       \
  do {                                                                         \
    TAILQ_FIRST((head)) = NULL;                                                \
    (head)->tqh_last = &TAILQ_FIRST((head));                                   \
  } while (0)

#define	TAILQ_EMPTY(head) ((head)->tqh_first == NULL)

#define TAILQ_REMOVE(head, elm, field) {                                \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
}

#define TAILQ_FOREACH(var, head, field)                                        \
  for ((var) = TAILQ_FIRST((head)); (var); (var) = TAILQ_NEXT((var), field))

#define TAILQ_INSERT_TAIL(head, elm, field)                                    \
  do {                                                                         \
    TAILQ_NEXT((elm), field) = NULL;                                           \
    (elm)->field.tqe_prev = (head)->tqh_last;                                  \
    *(head)->tqh_last = (elm);                                                 \
    (head)->tqh_last = &TAILQ_NEXT((elm), field);                              \
  } while (0)

#endif
