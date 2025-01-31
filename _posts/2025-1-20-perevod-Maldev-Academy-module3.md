---
layout: post
title: "Модуль 3 MalDev Academy на русском"
---

**Модуль 3 "PE файлы от Maldev Academy на русском"**

![]({{ site.baseurl }}/images/m30.jpg)

PE — это исполняемые файлы в Винде. Сюда входят: `.exe`, `.dll`, `.sys` и `.scr`. В модуле кратко рассказывается про структуру PE file, это необходимо для реверса, малварь аналитики и малварьдева

***PE Structure***

Ниже схематично изображена структура Portable Executable. Каждый заголовок, что есть на картинке содержит инфу о PE-файле.

![]({{ site.baseurl }}/images/m33.jpg)

***DOS Header (IMAGE_DOS_HEADER)***

![]({{ site.baseurl }}/images/m31.jpg)

DOS Header всегда имеетс префикс из двух байтов `0x4D` и `0x5A`, обычно называемый `MZ`. Они нужны для подтверждения того, что файл ялвяется PE. Структура данных DOS Header выглядит, как на примере:

```
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Константа для индетификации файла как PE
    WORD   e_cblp;                      // Константа указывающая на количество байт в конце файла, необходима для обратной совместимости с MS-DOS
    WORD   e_cp;                        // Количество полных страниц файла
    WORD   e_crlc;                      // Количество записей в таблице перемещений, актуально для DOS
    WORD   e_cparhdr;                   // Количество параграфов в заголовке
    WORD   e_minalloc;                  // Минимальное количество дополнительных параграфов памяти, актуально для MS-DOS
    WORD   e_maxalloc;                  // Максимальное количество дополнительных параграфов памяти, актуально для MS-DOS
    WORD   e_ss;                        // Содержит относительное значение сегмента стека, актуально для MS-DOS
    WORD   e_sp;                        // Cодержит начальное значение регистра SP, актуально для MS-DOS
    WORD   e_csum;                      // Контрольная сумма, актуально для MS-DOS 
    WORD   e_ip;                        // Позволяет указать точку входа в программу, то есть адрес первой инструкции, которую нужно выполнить, актуально для MS-DOS 
    WORD   e_cs;                        // Позволяет указать адрес памяти кода, актуально для MS-DOS
    WORD   e_lfarlc;                    // Указывает где находится таблица перемещений, актуально для MS-DOS 
    WORD   e_ovno;                      // Номер оверлея, актуально для MS-DOS 
    WORD   e_res[4];                    // Зарезервированные поля, актуально для MS-DOS
    WORD   e_oemid;                     // Индетификатор OEM, актуально для MS-DOS 
    WORD   e_oeminfo;                   // Содержит специфическую инфу о OEM, актуально для MS-DOS 
    WORD   e_res2[10];                  // 20 байт были зарезервированы для потенциальных будущих расширений формата,  актуально для MS-DOS 
    LONG   e_lfanew;                    // Смещение к началу NT header, Он содержит информацию о структуре файла, необходимые адреса, размеры секций, информацию об импорте и экспорте 
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```
Самыми важными в этой структуре являются:
 - `e_magic` составляет 2 байта с фиксированным значением `0x5A4D` или `MZ`.

 - `e_lfanew` — это 4-байтовое значение, которое содержит смещение к началу заголовка NT. Надо помнить, что `e_lfanew` всегда располагается по смещению `0x3C`.
 
***DOS Stub*** 

DOS Stub - это не заголовок PE, но о нем полезно знать. Это своего рода заглушка. Её основная задача - отобразить сообщение об ошибке, если PE-файл пытаются запустить в MS-DOS.

***NT Header (IMAGE_NT_HEADERS)***

NT Header необходим, поскольку он включает в себя два других заголовка образа: `FileHeader` и `OptionalHeader`, которые включают большой объем информации о файле PE. Подобно заголовку DOS, заголовок NT содержит элемент подписи, который используется для его проверки. Обычно элемент подписи равен строке "PE", которая представлена ​​байтами `0x50` и `0x45`. Но поскольку подпись имеет тип данных `DWORD`, подпись будет представлена ​​как `0x50450000`, что по-прежнему является "PE", за исключением того, что она дополнена двумя нулевыми байтами. К заголовку NT можно получить доступ с помощью `e_lfanew`.

Структура заголовка NT различается в зависимости от архитектуры машины.

 - 32-битная версия:

```
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```
 - 64-битная версия:

```
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

Единственное отличие — это `OptionalHeader` структура данных `IMAGE_OPTIONAL_HEADER32` и `IMAGE_OPTIONAL_HEADER64`.

***File Header (IMAGE_FILE_HEADER)***

Наиболее важными членами структуры являются:

 - `NumberOfSections` - Количество разделов в PE-файле.

 - `Characteristics` - Флаги, которые определяют определенные атрибуты исполняемого файла, например, является ли он библиотекой динамической компоновки (DLL) или консольным приложением.

 - `SizeOfOptionalHeader` - Размер следующего необязательного заголовка

Общий вид структуры:

```
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

Дополнительную инфу о заголовке файла можно найти на [странице официальной документации](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header).

***Optional Header (IMAGE_OPTIONAL_HEADER)***

Необязательный заголовок важен, он необходим для выполнения PE-файла. Он называется необязательным, потому-что некоторые типы файлов его не имеют.
Необязательный заголовок имеет две версии: версию для 32-битных и 64-битных систем. Обе версии имеют почти идентичные элементы в своей структуре данных, а основное различие заключается в размере некоторых элементов. `ULONGLONG` используется в 64-битной версии и `DWORD` в 32-битной версии. Кроме того, в 32-битной версии есть некоторые элементы, которые отсутствуют в 64-битной версии.

 - 32-битная версия:

```
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

 - 64-битная версия:
 
 ```
 typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  ULONGLONG            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  ULONGLONG            SizeOfStackReserve;
  ULONGLONG            SizeOfStackCommit;
  ULONGLONG            SizeOfHeapReserve;
  ULONGLONG            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```
Необязательный заголовок содержит массу информации, которую можно использовать. Ниже приведены некоторые из членов структуры, которые обычно используются:

 - `Magic` - Описывает состояние файла изображения (32- или 64-битное изображение)

 - `MajorOperatingSystemVersion` - Основной номер версии требуемой операционной системы (например, 11, 10)

 - `MinorOperatingSystemVersion` - Дополнительный номер версии требуемой операционной системы (например, 1511, 1507, 1607)

 - `SizeOfCode` - Размер раздела `.text`

 - `AddressOfEntryPoint` - Смещение к точке входа файла (обычно основная функция)

 - `BaseOfCode` - Смещение к началу `.text` раздела

 - `SizeOfImage` - Размер файла изображения в байтах

 - `ImageBase` - Он указывает предпочтительный адрес, по которому приложение должно быть загружено в память при его выполнении. Из-за ASLR, редко можно увидеть изображение, сопоставленное с его предпочтительным адресом, поскольку загрузчик Windows PE сопоставляет файл с другим адресом. Это случайное распределение, выполненное загрузчиком Windows PE, может вызвать проблемы при реализации будущих методов. 

 - `DataDirectory` - Один из самых важных членов в необязательном заголовке. Это массив IMAGE_DATA_DIRECTORY , который содержит каталоги в PE-файле
 
***Data Directory***

Это массив типа данных `IMAGE_DATA_DIRECTORY`, который имеет следующую структуру данных:

```
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
Массив Data Directory имеет размер `IMAGE_NUMBEROF_DIRECTORY_ENTRIES`, который является постоянным значением `16`. Каждый элемент массива представляет собой определенный каталог данных, который включает некоторые данные о разделе PE или таблице данных (место, где сохраняется определенная информация о PE).

Доступ к определенному каталогу данных можно получить, используя его индекс в массиве.

```
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Экспорт директория
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Импорт Директория
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Каталог Ресурсов
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Каталог Исключений
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Каталог Безопасности
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Указатель на таблицу перемещений базы 
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Директория отладки
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Архитектурно-зависимые данные
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // Указывает на RVA
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // Указывает на директорию TLS
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Указывает на директорию конфигурации загрузки
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Указывает на директорию связанных импортов(которая содержит инфу о DLL)
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Указывает на таблицу адресов импорта 
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Указывает на дескрипторы отложенной загрузки импорта
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // Указывает на дескриптор COM-среды выполнения
```

В двух разделах ниже кратко упоминаются два важных каталога данных: `Export Directory` и `Import Address Table`.

***Export Directory***

Export Directory PE — это структура данных, которая содержит информацию о функциях и переменных, экспортируемых из исполняемого файла. Он содержит адреса экспортируемых функций и переменных, которые могут использоваться другими исполняемыми файлами для доступа к функциям и данным. Каталог экспорта обычно находится в библиотеках DLL, экспортирующих функции (например, `kernel32.dll` экспорт `CreateFileA`).

***Import Address Table***

Import Address Table — это структура данных в PE, которая содержит информацию об адресах функций, импортированных из других исполняемых файлов. Адреса используются для доступа к функциям и данным в других исполняемых файлах (например, `Application.exe` импорт `CreateFileA` из `kernel32.dll`).

***PE Sections***

Следующие разделы являются наиболее важными и присутствуют почти в каждом PE.

 - `.text` - Содержит исполняемый код, представляющий собой написанный код.

 - `.data` - Содержит инициализированные данные, представляющие собой переменные, инициализированные в коде.

 - `.rdata` - Содержит данные только для чтения. Это постоянные переменные с префиксом const.

 - `.idata` - Содержит таблицы импорта. Это таблицы информации, относящиеся к функциям, вызываемым с использованием кода. Это используется загрузчиком Windows PE для определения того, какие файлы DLL следует загрузить в процесс, а также какие функции используются из каждой DLL.

 - `.reloc` - Содержит информацию о том, как исправить адреса памяти, чтобы программа могла быть загружена в память без ошибок.

 - `.rsrc` - Используется для хранения таких ресурсов, как значки и растровые изображения.

Каждый раздел PE имеет структуру данных `IMAGE_SECTION_HEADER`, которая содержит ценную информацию о нем. Эти структуры сохраняются под заголовками NT в файле PE и располагаются друг над другом, где каждая структура представляет раздел.

Пример `IMAGE_SECTION_HEADER`

```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

 - `Name` - Имя раздела. (например, .text, .data, .rdata).

 - `PhysicalAddress` или `VirtualSize` - Размер раздела, когда он находится в памяти.

 - `VirtualAddress` - Смещение начала раздела в памяти.

***Conclusion***

![]({{ site.baseurl }}/images/m32.jpg)

Структуру PE довольно сложно понять, когда ты видишь ее в первый раз. Для части модулей, достаточно очень базового понимания и представления, что такое структура PE файла и этого хватит для малварь аналитики и малварьдева, если захотите позадротить, то вот дополнительное чтиво, [статья с Codeby](https://codeby.net/threads/0x01-issleduyem-portable-executable-exe-fail-format-pe-faila.65415/), где разобрано все довольно подробно.

Этот модуль без ДЗ, пусть домашним заданием будет подписаться на мой канал или не отписываться, если уже подписан. https://t.me/l33trfm0x
