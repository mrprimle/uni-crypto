# uni-crypto

<b>ElGamal:</b>
Шифрування ElGamal є криптосистемою з відкритим ключем. Він використовує шифрування з асиметричним ключем для спілкування між двома сторонами та шифрування повідомлення. Ця криптосистема заснована на труднощі знаходження дискретного логарифма в циклічній групі, тобто навіть якщо ми знаємо ga і gk, обчислити gak надзвичайно важко.

Ідея криптосистеми ElGamal:
Припустимо, Аліса хоче поспілкуватися з Бобом.

Боб генерує відкритий і закритий ключі:
Боб вибирає дуже велике число q і циклічну групу Fq.
З циклічної групи Fq він вибере будь-який елемент g і
елемент a такий, що gcd(a, q) = 1.
Потім він обчислює h = ga.
Боб публікує F, h = ga, q і g як свій відкритий ключ і зберігає a як закритий ключ.
Аліса шифрує дані за допомогою відкритого ключа Боба:
Аліса вибирає елемент k із циклічної групи F
так, що gcd(k, q) = 1.
Потім вона обчислює p = gk і s = hk = gak.
Вона множить s на M.
Потім вона посилає (p, M*s) = (gk, M*s).
Боб розшифровує повідомлення:
Боб обчислює s′ = pa = gak.
Він ділить M*s на s′, щоб отримати M як s = s′.

У цій криптосистемі вихідне повідомлення M маскується шляхом множення gak на нього. Щоб зняти маску, дається підказка у формі gk. Якщо хтось не знає a, він не зможе отримати M. Це тому, що знайти дискретний журнал у циклічній групі важко, а спрощення знання ga та gk недостатньо добре для обчислення gak.

Переваги:
Безпека: ElGamal базується на задачі дискретного логарифмування, яку вважають важкою для вирішення. Це робить його захищеним від атак хакерів.
Розподіл ключів: ключі шифрування та дешифрування відрізняються, що полегшує безпечне розповсюдження ключів. Це забезпечує безпечний зв’язок між кількома сторонами.
Цифрові підписи: ElGamal також можна використовувати для цифрових підписів, що забезпечує безпечну автентифікацію повідомлень.
Недоліки:
Повільна обробка: ElGamal повільніший порівняно з іншими алгоритмами шифрування, особливо при використанні з довгими ключами. Це може зробити його непрактичним для певних програм, які потребують високої швидкості обробки.
Розмір ключа: ElGamal вимагає більшого розміру ключа для досягнення того самого рівня безпеки, що й інші алгоритми. Це може ускладнити використання в деяких програмах.
Уразливість до певних атак: ElGamal вразливий до атак, заснованих на проблемі дискретного логарифмування, наприклад алгоритму обчислення індексу. Це може знизити безпеку алгоритму в певних ситуаціях.



<b>Rabin:</b>
Криптосистема Рабіна — це криптосистема з відкритим ключем, винайдена Майклом Рабіном. Він використовує шифрування з асиметричним ключем для спілкування між двома сторонами та шифрування повідомлення.

Безпека криптосистеми Рабіна пов'язана зі складністю факторизації. Його перевага над іншими полягає в тому, що проблема, на яку він спирається, виявилася важкою, як цілочисельна факторізація. Вона також має недолік, що кожен вихід функції Рабіна може бути згенерований будь-яким із чотирьох можливих входів. якщо кожен вихід є зашифрованим текстом, потрібна додаткова складність дешифрування, щоб визначити, який із чотирьох можливих входів був справжнім відкритим текстом.

Кроки в криптосистемі Рабіна

1) Генерація ключів:
Згенеруйте два дуже великі прості числа, p і q, які задовольняють умову
p ≠ q → p ≡ q ≡ 3 (mod 4)
Наприклад:
  p=139 і q=191
2) Обчисліть значення n
  n = p.q
3) Опублікуйте n як відкритий ключ і збережіть p і q як закритий ключ
Шифрування
4) Отримайте відкритий ключ n.
5) Перетворіть повідомлення на значення ASCII. Потім перетворіть його на двійкове та доповніть двійкове значення самим собою, а потім знову змініть двійкове значення на десяткове m.
6) Зашифруйте формулою:
C = m2 mod n
7) Надіслати C одержувачу.

Розшифровка:
1) Прийняти C від відправника.
2) Укажіть a і b за допомогою розширеного евклідового НОД так, щоб a.p + b.q = 1
3) Обчисліть r і s за такою формулою:
r = C(p+1)/4 mod p
s = C(q+1)/4 mod q
4) Тепер обчисліть X і Y за такою формулою:
X = (a.p.r + b.q.s) mod p
Y = (a.p.r – b.q.s) mod q
5) Чотири корені: m1=X, m2=-X, m3=Y, m4=-Y
6) Тепер перетворіть їх у двійковий і розділіть навпіл.
7) Визначте, у яких ліва і права половини однакові. Збережіть двійкову половину та перетворите її на десяткову m. Отримайте символ ASCII для десяткового значення m. Отриманий символ означає правильне повідомлення, надіслане відправником.











