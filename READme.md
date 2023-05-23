

# JIT-компилятор (МФТИ 2023)
____

## Цель работы
Исследование процесса JIT-компиляции и кодирования команд ассемблера x86.

## Введение
**JIT-компиляция** (*Just-in-time*) или **динамическая компиляция** - компиляция *байт-кода* в машинный непосредственно во время исполнения программы. Данная технология используется для увеличения скорости выполнения программы, в сравнении с сохраняемым байт-кодом, за счёт выделения памяти под исполняемый буфер и затрат на саму компиляцию, а также для реализации более гибких оптимизаций за счёт возможности их осуществления прямо во время исполнения. **Байт-код** представляет из себя компактное промежуточное представление программы в побитовом виде, которое позволяет осуществлять быстрое взаимодействие между частями системы.


## Реализация
В данной работе будем компилировать байт-код, созданный собственным ассемблером из репозитория https://github.com/Art8mish/Processor. В учебных целях синтаксис сильно урезан, по сравнению с реальным ассемблером x86, и представляет из себя небольшой набор команд, которые и будут транслироваться в исполняемый буфер. Регистров также сильно меньше (`rax`, `rcx`, `rdx`, `rbx`), но для реализации команд будут использованы также `rdi` и `rsi`. Дальше будут представлены сами инструкции и частично разобран принцип кодирования в архитектуре x86-64.

### Команды собственного ассемблера

</b></details>
<details>   
<summary> Список команд </summary><br><b>

- PUSH reg/mem/cnst
- POP reg/mem

- JMP
- CALL
- RET

- JB
- JBE
- JA
- JAE
- JE
- JNE

- ADD
- SUB
- MUL
- DIV

- OUT
- IN
- HLT
</b></details>

Команда PUSH помещает в стек константу, значение регистра или значение ячейки памяти, POP аналогично забирает значение из стека и кладёт в регистр или ячейку памяти (в нашем случае будем использовать только регистр). JMP и CALL представляют из себя переходы, в качестве аргумента принимается метка, RET является точной копией ассемблерного *ret*. Дальше представлены условные переходы, которые берут два значения из стека и в зависимости от условия производят переход. Арифметические команды ADD, SUB, MUL и DIV аналогично извлекают два значения из стека, производят операцию и заталкивают результат в стек. OUT выводит в консоль последнее значение в стеке, IN принимает значение из консоли и заталкивает в стек. HLT - команда завершения процесса.

#### Дальше представлены их реализации на ассемблере x86:

- PUSH 5
```asm
push 0x00000005
```

Все числа-константы будут задаваться в 32-разрядном виде (4 байта).

- PUSH/POP rax
```asm
push/pop rax
```


- PUSH/POP [2988 + RAX]
```asm
push/pop [rax + 0x00000BAC]
```


- JMP/CALL 0xEDA
```asm
jmp/call 0x00000EDA
```



- RET
```asm
ret
```

- JB/JBE/JA/JAE/JE/JNE 0xEDA
```asm
pop rsi
pop rdi
cmp rdi, rsi
jb/jbe/ja/jae/je/jne 0x00000EDA
```
При данных инструкциях используется относительная адресация, которая напрямую зависит от длины каждой инструкции.


- ADD/SUB/MUL
```asm
pop rsi
pop rdi
add/sub/imul rdi, rsi
push rdi
```
Стоит отметить, что знаковое умножение *mul* в ассемблерном виде можно представить как *imul*.


- DIV
```asm
pop rsi
pop rdi
push rax
push rdx
mov rax, rdi
idiv rsi
mov rdi, rax
pop rdx
pop rax
push rdi
```
Конструкция деления довольно велика, по сравнению с остальными командами, а также сильно медленнее. Об особенностях *div* и *idiv* можно прочитать на сайте https://www.club155.ru/x86cmd/IDIV.


- OUT
```asm
movabs rdi, str
pop rsi
push rax
movabs rax, printf_ptr
call rax
pop rax
```
Для вывода чисел используется функция *printf*, указатель на которую копируется в *rax* с помощью `movabs`. Данная инструкция позволяет загрузить абсолютный адрес функции, который в памяти будет представлен в 64-разрядном виде (8 байт) и вызвать её с помощью *call*.

- IN
```asm
mov rdi, rax
movabs rax, __scanf
call rax
push rax
mov rax, rdi
```

Так как в данной задаче не нужен полный функционал *scanf* и память для аргумента выделять довольно проблематично, напишем свою сильно упрощенную версию *__scanf* и будем вызывать её.

</b></details>
<details>   
<summary> __scanf </summary><br><b>

```C++
int __scanf()
{
    int num = 0;
    char buf[32] = {0};

    read (0, buf, 32);
    int i = 0;
    while (buf[i] >= '0')
    {
        num *= 10;
        num += buf[i] - '0';
        i += 1;
    }

    return num;
}
```
</b></details>

- HLT
```asm
ret
```
Вместо HLT будем использовать *ret*, так как исполняемый буфер вызывается как функция с помощью *call*.


## Кодирование инструкций x86-64

В данной работе будут разобраны лишь поверхностные принципы кодирования команд ассемблера архитектуры x86-64, подробнее можно прочитать на сайтах, указанных в разделе источников о кодировании команд x86. Если зяглянуть в таблицу http://sparksandflames.com/files/x86InstructionChart.html, можно заметить, что команды сначала кодировались одним байтом, но с развитием технологий одного байта перестало хватать и сейчас большинство стандартных инструкции представляются в виде одного, двух или трёх байтов. В нашем случае хватит двух, первый байт таких двухбайтных команд - `0x0F`.

Далее для кодирования инструкций будет очень удобно использовать битовые поля, о них подробней можно прочитать на сайте https://russianblogs.com/article/1208846117/. Битовые поля позволяют адресоваться к отдельным битам, что будет очень полезно в данной работе.

</b></details>
<details>   
<summary> Структура из двух байтов для кодирования самой команды </summary><br><b>

```C++
struct Opcode
{
    int8_t b1 : 8;
    int8_t b2 : 8;
};
```
</b></details>

Дальше для адресации операндов используется байт `ModRM`, состоящий из трёх полей: *mod*, *reg*, *rm*. 

~~~
+-------------------------------+
|            ModRM              |
|-------------------------------|
| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | 
|  mod  |    reg    |    rm     |
+-------+-----------+-----------+
~~~

С помощью него можно закодировать адресацию *[reg_b + reg_r + offs]*, где *reg_b* - база (поле reg), относительно которой производится смещение, а *reg_r* и *offs* - регистр общего назначения и константа смещения. Поле *mod* состоит и двух байтов и в совокупности с остальными полями позволяет кодировать разные комбинации данной адресации. Поле *reg* также может быть использовано для кодирования разных вариантов похожих команд.

</b></details>
<details>   
<summary> Структура ModRm </summary><br><b>

```C++
struct ModRMb
{
    int8_t rm  : 3;
    int8_t reg : 3;
    int8_t mod : 2;
};
```
</b></details>


Для адресации с помощью конструкции *[reg_b * scale + reg_r + offs]* используется следующий опциональный байт `SIB` (для этого в поле *rm* указывается его код `0b100`).

~~~
+-------------------------------+
|             SIB               |
|-------------------------------|
| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | 
| scale |   index   |   base    |
+-------+-----------+-----------+
~~~

`SIB` также состоит из трёх полей: *scale*, *index* и *base*, где *scale* - индекс, принимающий значения {1, 2, 4, 8}, *base* - это регистр-база (*reg_b*) и *index* - *reg_r* соответсвенно, *offs* по аналогии константное смещение. 

Дальше может идти сама константа в 1-байтном, 4-байтном или 8-байтном виде в зависимости от инструкции.

</b></details>
<details>   
<summary> Структура SIB </summary><br><b>

```C++
struct SIBb
{
    int8_t base  : 3;
    int8_t index : 3;
    int8_t scale : 2;
};
```
</b></details>

Также стоит упомянуть о префиксах для некоторых инструкций, они нужны для разных целей, например, для указания размера регистра-операнда (eax -> ax) или для кодирования *repnz* и *rep*, подробнее есть возможность прочитать на сайте https://habr.com/ru/companies/intel/articles/200598/. В данной работе работе будет достаточно знания префикса `REX` вида 0x4* (в нашем случае 0x48), кодирующего работу в 64-битном режиме.

> Обо всех тонкостях кодировок следует узнавать из официальных мануалов архитектур процессоров.

## IR

Для удобства работы с каждой инструкцией будем переводить байт-код сначала в некоторое промежуточное представление `IR`(Intermediate Representation). Данный метод широко применяется для увеличения степени удобства работы между разными частями компиляторных систем, таких как фронтенд, миддленд, бэкенд и т.п. *IR* представляет из себя общую систему представления исходного кода и позволяет производить дальнейшие обработки и оптимизации. В нашем случае она будет близко к кодировке инструкций x86.

~~~
+--------+                 +---------------+
|PUSH 1  |                 |0x68 0x00000001|
|POP RBX |-----> IR -----> |0x5b           |
+--------+                 +---------------+
~~~

</b></details>
<details>   
<summary> Итоговая структура инструкции IR</summary><br><b>

```C++
struct IRitem
{
    int8_t prfx = 0x00;

    struct Opcode cmd;

    struct ModRMb ModRM;
    struct SIBb   SIB;

    int64_t cnst = PSN_CNST;

    uint8_t instr_len = 0;
};
```

</b></details>

## Исполнение буфера, mprotect.

Теперь байт-код можно транслировать в IR, который позволит создать буфер закодированных иинструкций x86. Буффер виртуальной памяти даёт возможность выделить функция `mmap` из библиотеки *<sys/mman.h>*. Подробнее об использовании и возможностях этой функции можно прочитать по ссылкам в источниках в соответствующем параграфе. 

К прочему, буфер должен иметь права на исполнение, которые позволяет выдать функция `mprotect`.

Исполнить буфер можно с помощью ассемблерной вставки

```C++
__asm__ ("call %0\n\t" :: "r" (ex_code->buf));
```

Сравнение времени исполнения программы, вычисляющей факториал 5 на собственной имитации процессора и при JIT-компиляции.

|        |   t, с   |
|:------:|:--------:|
| My cpu | 0.000345 |
|  JIT   | 0.000095 |


## Выводы

В данной работе были поверхностно разобраны понятия JIT-компиляции, байт-кода и IR, а также система кодирования инструкций x86. Была реализована JIT-компиляция байт-кода в исполняемый буфер.

JIT-компиляция оставляет большой простор для динамической оптимизации программ прямо во время исполнения, что может показать большой прирост в скорости исполнения.

В данной работе были использованы онлайн-ассемблеры https://shell-storm.org/online/Online-Assembler-and-Disassembler/ и https://defuse.ca/online-x86-assembler.htm#disassembly, а также онлайн-компилятор https://godbolt.org/.

## Источники и литература
1. JIT-компиляция и байт-код:
    - https://ru.wikipedia.org/wiki/JIT-компиляция
    - https://ru.wikipedia.org/wiki/Байт-код

2. Кодирование команд x86 (справки и мануалы):
    - http://ref.x86asm.net/index.html
    - https://wasm.in/threads/principy-kodirovanija-instrukcij-intel-x86-64-ili-exal-prefiks-cherez-prefiks.34390/
    - https://osdev.fandom.com/ru/wiki/Кодирование_команд

3. Кодирование команд x86 (таблицы):
    - http://sparksandflames.com/files/x86InstructionChart.html
    - http://ref.x86asm.net/coder64.html#two-byte
    - https://shell-storm.org/x86doc/

4. Префиксы
    - https://habr.com/ru/companies/intel/articles/200598/


5. Битовые поля:
    - https://ru.wikipedia.org/wiki/Битовое_поле_(C%2B%2B)
    - https://habr.com/ru/articles/142662/
    - https://russianblogs.com/article/1208846117/

6. IR:
    - https://ru.wikipedia.org/wiki/Промежуточное_представление
    - https://habr.com/ru/articles/459704/


7. Руководства по mmap и mprotect:
    - https://www.opennet.ru/cgi-bin/opennet/man.cgi?topic=mmap&category=2
    - https://www.opennet.ru/man.shtml?topic=mprotect&category=2&russian=0
    - https://linuxhint.com/using_mmap_function_linux/
    - https://it.wikireading.ru/34325

8. Остальные использованные полезные материалы
    - https://www.club155.ru/x86cmd/IDIV

9. Онлайн-компилятор GodBolt
    - https://godbolt.org/

10. Ассемблирование команд x86
    - https://shell-storm.org/online/Online-Assembler-and-Disassembler/
    - https://defuse.ca/online-x86-assembler.htm#disassembly

11. Официальный мануал архитектуры AMD64
    - https://www.cs.utexas.edu/~vijay/cs378-f17/projects/AMD64_Architecture_Programmers_Manual.pdf

Литература:
- Randal E. Bryant and David R. O'Hallaron "Computer Systems: A Programmer's Perspective"
